from xmlrpc.server import SimpleXMLRPCServer
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Any
import threading
import idaapi
import idautils


class FunctionNames(Enum):
    LIST_FUNCTIONS = "list_functions"
    DECOMPILE_FUNCTION = "decompile_function"
    DISASSEMBLE_FUNCTION = "disassemble_function"
    GET_PATH = "get_path"


class BaseFunctionRequest:
    def __init__(self, event: threading.Event):
        self.event = event
        self.result: Any = None

    def __call__(self):
        try:
            self.execute()
        except Exception as e:
            self.result = f"Error: {e}"
        finally:
            self.event.set()

    def execute(self):
        """Subclasses must implement this method."""
        raise NotImplementedError("Execute method must be implemented in subclasses.")

class ListFunctionsRequest(BaseFunctionRequest):
    def execute(self):
        """
        Lists functions defined in the current IDA database, excluding imported functions.
        """
        function_names = self.list_all_functions()
        self.result = "\n".join(function_names)

    def list_all_functions(self) -> list:
        """
        Retrieve all functions from the current binary, based on its file type.
        """
        file_type = idaapi.get_file_type_name()

        if "ELF" in file_type:
            functions = self._get_functions_elf()
        elif "PE" in file_type:
            functions = self._get_functions_pe()
        else:
            idaapi.msg(f"[IDAScope] Unsupported file type: {file_type}\n")
            functions = set()

        return sorted(functions)

    def _get_functions_elf(self) -> set:
        """
        Retrieve all functions from an ELF binary, including resolving external functions.
        """
        functions = set()

        for func_ea in idautils.Functions():
            segment_name = idaapi.get_segm_name(idaapi.getseg(func_ea))

            if segment_name == 'extern':
                func_name = self._resolve_extern(func_ea)
            else:
                func_name = idaapi.get_func_name(func_ea)

            if func_name:
                functions.add(func_name)

        # Handle special ELF-specific sections
        extern_functions = {func for func in functions if "extern" in func}
        plt_functions = {func for func in functions if ".plt" in func}

        # Include or exclude based on XOR logic
        return functions.union(extern_functions ^ plt_functions)

    def _get_functions_pe(self) -> set:
        """
        Retrieve all functions from a PE binary, including imports and exports.
        """
        functions = {idaapi.get_func_name(func_ea) for func_ea in idautils.Functions() if idaapi.get_func_name(func_ea)}
        functions.update(self._get_imported_functions())
        functions.update(self._get_exported_functions())
        return functions

    def _get_imported_functions(self) -> list:
        """
        Enumerate imported functions from the Import Address Table (IAT) in PE binaries.
        """
        imported_functions = set()

        def import_enum_callback(ea, name, ordinal):
            if name:
                imported_functions.add(name)
            return True

        for i in range(idaapi.get_import_module_qty()):
            idaapi.enum_import_names(i, import_enum_callback)

        return sorted(imported_functions)

    def _get_exported_functions(self) -> list:
        """
        Enumerate exported functions from the Export Address Table (EAT) in PE binaries.
        """
        exports = []
        for entry in idautils.Entries():
            try:
                ordinal, ea, name = entry
                if name:
                    exports.append(name)
            except ValueError:
                idaapi.msg(f"[IDAScope] Unexpected entry format: {entry}\n")
        return sorted(set(exports))

    def _resolve_extern(self, ea) -> str:
        """
        Resolve external function references for both ELF and PE binaries.
        """
        func_name = idaapi.get_func_name(ea)
        if not func_name:
            return None

        extern_ea = idaapi.get_name_ea(idaapi.BADADDR, func_name)
        if extern_ea == idaapi.BADADDR:
            return None

        for xref_extern_ea in idautils.XrefsTo(extern_ea, idaapi.XREF_ALL):
            if not xref_extern_ea.iscode:
                continue

            xref_type = idaapi.xrefchar(xref_extern_ea.type).lower()
            if xref_type in {'j', 'i'}:  # 'j' for ELF, 'i' for PE
                func = idaapi.get_func(xref_extern_ea.frm)
                if func:
                    return idaapi.get_name(func.start_ea)

        return None

class GetPathRequest(BaseFunctionRequest):
    def __init__(self, func_name: str, event: threading.Event):
        super().__init__(event)
        self.func_name = func_name

    def execute(self):
        parent_path = Path(idaapi.get_input_file_path()).resolve().parent
        binary_name = Path(idaapi.get_input_file_path()).name
        file_path_dir = parent_path / f"{binary_name}_functions"
        file_path_dir.mkdir(exist_ok=True)
        self.result = str(file_path_dir / self.func_name)

class DecompileFunctionRequest(BaseFunctionRequest):
    def __init__(self, func_name: str, filename: str, event: threading.Event):
        super().__init__(event)
        self.func_name = func_name
        self.filename = filename

    def execute(self):
        """
        Attempts to decompile a function. If decompilation fails, fallback to disassembly.
        """
        self.filetype = idaapi.get_file_type_name()
        try:
            ea = idaapi.get_name_ea(idaapi.BADADDR, self.func_name)

            # Check for cached cfunc
            if idaapi.has_cached_cfunc(ea):
                idaapi.clear_cached_cfuncs()

            cfunc_t = idaapi.decompile(ea)
            if not cfunc_t:
                # Decompilation failed. Falling back to disassembly
                disassembler = DisassembleFunctionRequest(self.func_name, self.filename, self.event)
                disassembler.execute()
                self.result += "\n" + disassembler.result
            else:
                self.result = str(cfunc_t)
        except Exception as e:
            self.result = f"IMPORT {self.func_name}" if "PE" in self.filetype else "[ERROR] Disassembly failed."


class DisassembleFunctionRequest(BaseFunctionRequest):
    def __init__(self, func_name: str, filename: str, event: threading.Event):
        super().__init__(event)
        self.func_name = func_name
        self.filename = filename

    def execute(self):
        """
        Disassembles a function, including:
        - Prototype.
        - Repeatable comments.
        - Stack frames.
        - Detailed disassembly lines with segment names and addresses.
        """
        self.filetype = idaapi.get_file_type_name()
        try:
            ea = idaapi.get_name_ea(idaapi.BADADDR, self.func_name)
            func_t = idaapi.get_func(ea)
            if not func_t:
                self.result = f"IMPORT {self.func_name}" if "PE" in self.filetype else "[ERROR] Disassembly failed."
                return

            result = []

            # Add prototype
            prototype = self._get_proto(func_t, ea, self.func_name)
            if prototype:
                result.append(prototype)

            # Add repeatable comments
            func_header = idaapi.get_func_cmt(func_t, True)
            if func_header:
                result.append(f"// {func_header}")

            # Add stack frame details
            frame_details = self._get_stack_frame(func_t)
            if frame_details:
                result.extend(frame_details)

            # Add disassembly lines
            disassembly_lines = self._get_disassembly_lines(func_t)
            result.extend(disassembly_lines)

            self.result = "\n".join(result)
        except Exception as e:
            self.result = f"Error during disassembly: {e}"


    def _get_proto(self, func, ea, func_name) -> str:
        prototype = ''
        if func:
            tif = idaapi.tinfo_t()
            if idaapi.get_tinfo(tif, func.start_ea):
                func_data = idaapi.func_type_data_t()
                if tif.get_func_details(func_data):
                    prototype = idaapi.print_tinfo('', 0, 1, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_PRAGMA, tif, func_name, f"{ea:#x}")
        return prototype



    def _get_stack_frame(self, func) -> list:
        """
        Extracts stack frame details for the given function.
        """
        stack = []
        if hasattr(idaapi, "get_frame"): #could do backward compatibility
            frame = idaapi.get_frame(func)
            if not frame:
                return []

            for member in idautils.StructMembers(frame.id):
                stack.append(f"// {member[1]} = 0x{member[0]:x}")
        else:
            frame_tif = idaapi.tinfo_t()
            frame_udt = idaapi.udt_type_data_t()
            if not idaapi.get_func_frame(frame_tif, func) or not frame_tif.get_udt_details(frame_udt):
                return []
            for udm in frame_udt:
                sval = idaapi.calc_frame_offset(func, udm.offset//udm.type.get_size(), None, None)-udm.offset//4
                stack.append(f"// {udm.name}\t =  {-1 * sval:#x} {udm.type.dstr()} {udm.cmt}")
        return stack

    def _get_disassembly_lines(self, func) -> list:
        """
        Generates disassembly lines with addresses and segment names.
        """
        lines = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            disasm_line = idaapi.generate_disasm_line(head, idaapi.GENDSM_FORCE_CODE)
            if disasm_line:
                segment_name = idaapi.get_segm_name(idaapi.getseg(head))
                lines.append(f"{segment_name}: {head:08X} {idaapi.tag_remove(disasm_line)}")
        return lines


class FunctionRequestFactory:
    @staticmethod
    def create_request(request_type: FunctionNames, **kwargs) -> BaseFunctionRequest:
        if request_type == FunctionNames.LIST_FUNCTIONS:
            return ListFunctionsRequest(kwargs['event'])
        elif request_type == FunctionNames.DECOMPILE_FUNCTION:
            return DecompileFunctionRequest(kwargs['func_name'], kwargs['filename'], kwargs['event'])
        elif request_type == FunctionNames.DISASSEMBLE_FUNCTION:
            return DisassembleFunctionRequest(kwargs['func_name'], kwargs['filename'], kwargs['event'])
        elif request_type == FunctionNames.GET_PATH:
            return GetPathRequest(kwargs['func_name'], kwargs['event'])
        else:
            raise ValueError(f"Unknown request type: {request_type}")


def handle_request(request_type: FunctionNames, **kwargs) -> str:
    """
    Centralized handler for scheduling and executing function requests.
    """
    event = threading.Event()
    request = FunctionRequestFactory.create_request(request_type, event=event, **kwargs)
    idaapi.execute_ui_requests([request])
    event.wait()
    return request.result


class XMLRPCServerManager:
    _instance = None  # Class-level variable to hold the singleton instance

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(XMLRPCServerManager, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, host: str = "localhost", port: int = 65432):
        # Prevent re-initialization of the singleton instance
        if hasattr(self, "_initialized") and self._initialized:
            return

        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
        self.registry: Dict[FunctionNames, Callable] = {}
        self._setup_registry()
        self._initialized = True

    def _setup_registry(self):
        """Registers available functions."""
        self.registry = {
            FunctionNames.LIST_FUNCTIONS: lambda: handle_request(FunctionNames.LIST_FUNCTIONS),
            FunctionNames.DECOMPILE_FUNCTION: lambda func_name, filename: handle_request(
                FunctionNames.DECOMPILE_FUNCTION, func_name=func_name, filename=filename
            ),
            FunctionNames.DISASSEMBLE_FUNCTION: lambda func_name, filename: handle_request(
                FunctionNames.DISASSEMBLE_FUNCTION, func_name=func_name, filename=filename
            ),
            FunctionNames.GET_PATH: lambda func_name: handle_request(FunctionNames.GET_PATH, func_name=func_name),
        }

    def start_server(self):
        """
        Starts the XML-RPC server in a separate thread. Only starts if the server is not already running.
        """
        try:
            # Create and start the server
            self.server = SimpleXMLRPCServer((self.host, self.port), allow_none=True)
            for name, func in self.registry.items():
                self.server.register_function(func, name.value)
            self.server.register_function(self.stop_server_method, "stop_server")

            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()

            self.running = True
            idaapi.msg(f"[IDAScope] XML-RPC server started on {self.host}:{self.port}\n")
        except Exception as e:
            idaapi.msg(f"[IDAScope] Failed to start server: {e}\n")
            self.running = False

    def stop_server(self):
        """
        Stops the XML-RPC server and ensures all resources are cleaned up.
        """
        if not self.running and self.server is None:
            return

        idaapi.msg("[IDAScope] Stopping server...\n")
        try:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
                self.server = None
        except Exception as e:
            idaapi.msg(f"[IDAScope] Error during server shutdown: {e}\n")

        if self.thread:
            try:
                self.thread.join(timeout=1)
                if self.thread.is_alive():
                    idaapi.msg("[IDAScope] Server thread did not terminate cleanly. Forcing shutdown.\n")
                    self.thread = None
            except Exception as e:
                idaapi.msg(f"[IDAScope] Error joining server thread: {e}\n")
            finally:
                self.thread = None

        self.running = False
        idaapi.msg("[IDAScope] Server stopped.\n")

    def stop_server_method(self):
        """
        XML-RPC accessible method to stop the server.
        """
        idaapi.msg("[IDAScope] XML-RPC shutdown signal received.\n")
        self.stop_server()

    def toggle_server(self):
        """
        Toggles the server state between running and stopped.
        """
        if self.running:
            self.stop_server()
        else:
            self.start_server()

class IDAScopePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "IDA Pro Python Plugin for Telescope Integration"
    help = "This plugin integrates IDA Pro with Neovim's Telescope."
    wanted_name = "IDAScope"
    wanted_hotkey = "Meta-Ctrl-t"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.manager = XMLRPCServerManager()
        self.manager.toggle_server()

    def term(self):
        self.manager.toggle_server() if XMLRPCServerManager().running else None

def PLUGIN_ENTRY():
    return IDAScopePlugin()

if __name__ == "__main__":
    manager = XMLRPCServerManager()
    manager.toggle_server()
