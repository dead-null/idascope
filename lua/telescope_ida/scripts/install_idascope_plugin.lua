-- lua/telescope_ida/scripts/install_idascope_plugin.lua
--
-- Handles installing the IDAScope Python plugin into the IDA Pro plugins directory.

local Path = require('plenary.path')
local log = require('telescope_ida.log')

local M = {}

--- Install the IDAScope Python plugin into IDA's plugin directory.
-- Attempts to create a symlink, if that fails, copies the file.
-- Creates a marker file to avoid reinstallations.
-- @param plugins_dir string The IDA plugins directory
-- @param verbose boolean Whether to print verbose messages
-- @param check_if_installed boolean Whether to skip if marker file exists
function M.install_idascope_plugin(plugins_dir, verbose, check_if_installed)
    if not plugins_dir or plugins_dir == "" then
        log.error("No plugins directory provided. Installation aborted.")
        return
    end

    local marker_path = Path:new(vim.fn.stdpath('data'), "telescope_ida_installed"):absolute()

    if check_if_installed then
        local marker_file = io.open(marker_path, "r")
        if marker_file then
            marker_file:close()
            if verbose then
                log.info("Installation already completed. Skipping.")
            end
            return
        end
    end

    local path_sep = package.config:sub(1,1)
    if path_sep == '\\' then
        plugins_dir = plugins_dir:gsub('/', '\\')
    else
        plugins_dir = plugins_dir:gsub('\\', '/')
    end

    local script_path = debug.getinfo(1, "S").source:sub(2)
    local script_dir = Path:new(script_path):parent():parent():parent():parent():absolute()

    local source = Path:new(script_dir, "plugins", "idascope_plugin.py"):absolute()
    local destination = Path:new(plugins_dir, "idascope_plugin.py"):absolute()

    if verbose then
        log.info("Resolved source path: " .. source)
        log.info("Resolved destination path: " .. destination)
    end

    if not Path:new(source):exists() then
        log.error("Source Python plugin not found at " .. source)
        return
    end

    if Path:new(destination):exists() then
        if verbose then
            log.info("IDAScope Python plugin already exists at " .. destination)
        end
        return
    end

    local symlink_command
    if vim.fn.has("win32") == 1 then
        symlink_command = string.format('mklink "%s" "%s"', destination, source)
    else
        symlink_command = string.format('ln -s "%s" "%s"', source, destination)
    end

    if verbose then
        log.info("Executing symlink command: " .. symlink_command)
    end

    local res = os.execute(symlink_command)

    if res == 0 then
        log.info("IDAScope Python plugin symlinked successfully to " .. destination)
    else
        if verbose then
            log.info("Symlinking failed. Attempting to copy the plugin instead.")
        end
        local copy_command
        if vim.fn.has("win32") == 1 then
            copy_command = string.format('copy "%s" "%s"', source, destination)
        else
            copy_command = string.format('cp "%s" "%s"', source, destination)
        end

        if verbose then
            log.info("Executing copy command: " .. copy_command)
        end

        local copy_res = os.execute(copy_command)

        if copy_res == 0 then
            log.info("IDAScope Python plugin copied successfully to " .. destination)
        else
            log.error("Failed to install the IDAScope Python plugin. Please copy it manually.")
            return
        end
    end

    local marker_file = io.open(marker_path, "w")
    if marker_file then
        marker_file:write("Installed")
        marker_file:close()
        if verbose then
            log.info("Installation marker created at " .. marker_path)
        end
    else
        log.error("Failed to create installation marker at " .. marker_path)
    end
end

return M
