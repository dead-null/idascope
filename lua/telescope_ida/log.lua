-- lua/telescope_ida/log.lua
--
-- Centralized logging for IDAScope. Provides info and error utilities.

local M = {}

--- Display an informational message.
-- @param msg string The message to display
function M.info(msg)
    vim.api.nvim_out_write('[IDAScope] ' .. msg .. '\n')
end

--- Display an error message.
-- @param err string The error message
function M.error(err)
    vim.api.nvim_err_writeln('IDAScope Error: ' .. tostring(err))
    vim.api.nvim_out_write('IDAScope Error: ' .. tostring(err) .. '\n')
end

return M
