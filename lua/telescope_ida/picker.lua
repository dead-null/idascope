-- lua/telescope_ida/picker.lua
--
-- Displays the Telescope picker for IDA functions and handles previewing and exporting.
-- Integrates with rpc.lua for data retrieval and uses log.lua for messaging.

local pickers = require('telescope.pickers')
local finders = require('telescope.finders')
local previewers = require('telescope.previewers')
local conf = require('telescope.config').values
local actions = require('telescope.actions')
local action_state = require('telescope.actions.state')

local rpc = require('telescope_ida.rpc')
local log = require('telescope_ida.log')
local config = require('telescope_ida.config')

local M = {}

-- Current preview content and type are stored here to allow exporting.
local current_preview_content = nil
local current_preview_type = nil

--- Write the current preview content to a file and open it.
-- Uses `rpc.get_path` to determine the file path.
-- @param func_name string The selected function name
local function export_and_open(func_name)
    rpc.get_path(func_name, function(path)
        if path then
            local c = config.get()
            local extension = ''
            if current_preview_type == 'asm' then
                extension = '.asm'
            elseif current_preview_type == 'c' then
                extension = c.default_extension
            end

            local full_path = path .. extension
            if current_preview_content then
                local file = io.open(full_path, "w")
                if file then
                    file:write(current_preview_content)
                    file:close()
                    log.info('Written content to ' .. full_path)
                    vim.cmd('edit ' .. full_path)
                else
                    log.error('Failed to write to ' .. full_path)
                end
            else
                log.error('No content to write')
            end
        else
            log.error('Failed to get binary path')
        end
    end)
end

--- Update the preview buffer with new content.
-- @param bufnr number The preview buffer number
-- @param content string The content to display
-- @param filetype string The filetype to set
local function update_preview(bufnr, content, filetype)
    vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(content, '\n'))
    vim.api.nvim_buf_set_option(bufnr, 'filetype', filetype)
    current_preview_content = content
    current_preview_type = filetype
end

--- Fetch and show decompiled code in the preview.
-- @param func_name string
-- @param bufnr number
local function show_decompiled(func_name, bufnr)
    rpc.decompile_function(func_name, function(content)
        if content then
            if string.sub(func_name, 1, 5) == "__imp" then
                update_preview(bufnr, content, 'asm')
                log.info('Loaded assembly for imported function: ' .. func_name)
            else
                update_preview(bufnr, content, 'c')
            end
        else
            log.error('Failed to get decompiled content')
        end
    end)
end

--- Fetch and show assembly in the preview.
-- @param func_name string
-- @param bufnr number
local function show_assembly(func_name, bufnr)
    rpc.disassemble_function(func_name, function(content)
        if content then
            update_preview(bufnr, content, 'asm')
            log.info('Loaded assembly for function: ' .. func_name)
        else
            log.error('Failed to get content')
        end
    end)
end

--- Show the Telescope picker for IDA functions.
-- Allows switching preview modes and exporting.
-- @param override_url string|nil Optional server URL for this invocation
function M.show_picker(override_url)
    local c = config.get()

    -- Temporarily override server_url if given
    local original_url = c.server_url
    if override_url then
        c.server_url = override_url
        if c.verbose then
            log.info("Using override server URL: " .. override_url)
        end
    end

    rpc.list_functions(function(funcs)
        -- Restore original URL after listing
        c.server_url = original_url

        if not funcs then
            log.error('Failed to fetch functions from server.')
            return
        end

        local func_list = vim.split(funcs, '\n', true)
        if vim.tbl_isempty(func_list) then
            log.error('No functions found.')
            return
        end

        pickers.new({}, {
            prompt_title = 'IDA Functions',
            finder = finders.new_table { results = func_list },
            sorter = conf.generic_sorter({}),
            previewer = previewers.new_buffer_previewer {
                define_preview = function(self, entry)
                    show_decompiled(entry.value, self.state.bufnr)
                end,
            },
            attach_mappings = function(prompt_bufnr, map)
                local function set_preview(action_func, filetype)
                    local entry = action_state.get_selected_entry()
                    if entry then
                        local picker = action_state.get_current_picker(prompt_bufnr)
                        local previewer = picker.previewer
                        action_func(entry.value, previewer.state.bufnr)
                    end
                end

                -- <C-a> for assembly
                map('i', '<C-a>', function()
                    set_preview(show_assembly, 'asm')
                end)
                map('n', '<C-a>', function()
                    set_preview(show_assembly, 'asm')
                end)

                -- <C-d> for decompiled
                map('i', '<C-d>', function()
                    local entry = action_state.get_selected_entry()
                    if entry then
                        local picker = action_state.get_current_picker(prompt_bufnr)
                        local previewer = picker.previewer
                        show_decompiled(entry.value, previewer.state.bufnr)
                    end
                end)
                map('n', '<C-d>', function()
                    local entry = action_state.get_selected_entry()
                    if entry then
                        local picker = action_state.get_current_picker(prompt_bufnr)
                        local previewer = picker.previewer
                        show_decompiled(entry.value, previewer.state.bufnr)
                    end
                end)

                actions.select_default:replace(function()
                    local entry = action_state.get_selected_entry()
                    if entry then
                        actions.close(prompt_bufnr)
                        export_and_open(entry.value)
                    end
                end)

                return true
            end,
        }):find()
    end)
end

return M
