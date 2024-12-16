# IDAScope

IDAScope is a Neovim plugin that integrates IDA Pro with Telescope, allowing efficient exploration and analysis of functions within IDA Pro directly from Neovim (btw).

## Features

- **Function Listing:** Retrieve and search functions from IDA Pro.
- **Previews:** View decompiled pseudocode or assembly code within Telescope.
- **Export Function Data:** Write previewed content to files with appropriate extensions.
- **Automated Installation:** Simplify the setup of the IDA Pro Python plugin.

## Installation

### Prerequisites

- **Neovim:** Ensure you have Neovim 0.5 or higher installed.
- **Telescope.nvim:** A highly extendable fuzzy finder over lists.
- **Plenary.nvim:** Lua library for Neovim plugins.

### IDA Python plugin
On first installation, the Neovim plugin runs a script automating the creation of symlink to your $IDAUSR/plugins directory per the `ida_plugins_dir` configuration option.

For example:
```
chris: ~/.idapro/plugins $ realpath idascope_plugin.py
/Users/chris/.local/share/nvim/lazy/idascope/plugins/idascope_plugin.py
```

### Usage
Once idascope is installed using the config provided, a shortcut command is created and can be called with `nvim -c IDAScope`.

To use, First start IDA with the `idascope_plugin.py` as a script to initialize the server or start the server within the UI. Then you can run `nvim -c IDAScope`

### Keybindings
  - `<C-a>`: Switch preview to assembly
  - `<C-d>`: Switch preview to decompiled code
  - `<CR>`: Export the currently previewed content to a file and open it

### Using Lazy.nvim

Add the following to your `lazy.nvim` configuration:

```lua
-- idascope.lua

return {
        "dead-null/idascope", url = "git@github.com:dead-null/idascope.git",
        dependencies = {
            "nvim-telescope/telescope.nvim",
            "nvim-lua/plenary.nvim",
        },
        config = function()
            local ida_plugin = require("telescope_ida")
            local telescope = require("telescope")

            telescope.setup {
                defaults = {
                    preview = {
                        scroll_strategy = "cycle",
                    },
                }
            }


            ida_plugin.setup {
                server_url = 'http://localhost:65432/', -- XML-RPC server URL
                default_extension = '.c', -- Default file extension for exported files
                verbose = false, -- Enable verbose logging
                ida_plugins_dir = '/path/to/your/IDAUSR/plugins', -- Specify the IDA Pro plugins directory
                check_if_installed = false, -- Check if the Python plugin is already installed
            }

            vim.keymap.set('n', '<leader>vv', function()
                ida_plugin.IDAScope() end, {
                    noremap = true,
                    silent = true,
                    desc = 'Open IDAScope with Telescope'
                })

            vim.api.nvim_create_user_command('IDAScope', function(args)
                local xml_url = args.args ~= '' and args.args or ida_plugin.ida_xml_server
                ida_plugin.IDAScope(xml_url) end, {
                    nargs = '?',
                    desc = 'IDAScope'
                })
        end
}

return local_plugins
```
