-- lua/telescope_ida/config.lua
--
-- Handles loading and merging user configuration with default values.

local M = {}

local default_config = {
    server_url = 'http://localhost:65432/',
    default_extension = '.c',
    verbose = false,
    ida_plugins_dir = nil,      -- Path to IDA Pro plugins directory
    check_if_installed = true,  -- Check if Python plugin is installed
}

local user_config = {}

--- Setup configuration by merging user options with defaults.
-- @param opts table User-provided options
function M.setup(opts)
    opts = opts or {}
    user_config = vim.tbl_deep_extend("force", {}, default_config, opts)
end

--- Get the current merged configuration.
-- @return table The current configuration
function M.get()
    return user_config
end

return M
