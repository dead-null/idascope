-- lua/telescope_ida/init.lua
--
-- Entry point for the IDAScope plugin. This file sets up the plugin configuration
-- and provides a user-facing command and key mapping to open the IDAScope Telescope picker.

local M = {}

local config = require("telescope_ida.config")
local log = require("telescope_ida.log")
local picker = require("telescope_ida.picker")
local install_script = require("telescope_ida.scripts.install_idascope_plugin")

--- Setup the IDAScope plugin.
-- Merges user options with defaults and optionally installs the IDA plugin.
-- @param opts table User configuration options
function M.setup(opts)
    config.setup(opts)
    local c = config.get()

    -- If ida_plugins_dir is specified, attempt installation
    if c.ida_plugins_dir then
        install_script.install_idascope_plugin(
            c.ida_plugins_dir,
            c.verbose,
            c.check_if_installed
        )
    else
        if c.verbose then
            log.info("ida_plugins_dir not specified. Skipping IDA Pro Python plugin installation.")
        end
    end
end

--- Command entry point to show the IDAScope Telescope picker.
-- @param url string|nil Optional URL to override the configured server_url for this invocation
function M.IDAScope(url)
    picker.show_picker(url)
end

return M
