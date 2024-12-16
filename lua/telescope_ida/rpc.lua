-- lua/telescope_ida/rpc.lua
--
-- Handles XML-RPC communication with the IDA Pro server.
-- Provides functions for listing functions, disassembling, decompiling, and retrieving paths.

local async = require('plenary.async')
local curl = require('plenary.curl')
local xml_parser = require('telescope_ida.xml_parser')
local config = require('telescope_ida.config')
local log = require('telescope_ida.log')

local M = {}

--- Internal helper to send an XML-RPC request synchronously.
-- @param method string The XML-RPC method name
-- @param params table A list of string parameters
-- @return string|nil The response or nil on error
local function xmlrpc_request(method, params)
    local c = config.get()
    local request_body = "<?xml version='1.0'?><methodCall><methodName>" .. method .. "</methodName>"
    if params and #params > 0 then
        request_body = request_body .. "<params>"
        for _, param in ipairs(params) do
            request_body = request_body .. "<param><value><string>" .. param .. "</string></value></param>"
        end
        request_body = request_body .. "</params>"
    else
        request_body = request_body .. "<params></params>"
    end
    request_body = request_body .. "</methodCall>"

    local response = curl.post(c.server_url, {
        body = request_body,
        headers = { ["Content-Type"] = "text/xml" },
        timeout = 5000,
    })

    if not response then
        log.error("No response from server")
        return nil
    end

    if response.status ~= 200 then
        log.error("HTTP error code: " .. tostring(response.status))
        return nil
    end

    local parsed = xml_parser.parse_response(response.body)
    if parsed.fault then
        log.error("XML-RPC Fault (" .. parsed.fault.code .. "): " .. parsed.fault.string)
        return nil
    elseif parsed.params and #parsed.params > 0 then
        return parsed.params[1]
    else
        log.error("Invalid XML-RPC response")
        return nil
    end
end

--- Send an XML-RPC request asynchronously.
-- @param method string The XML-RPC method name
-- @param params table Parameters for the call
-- @param callback function Called with the result or nil on failure
function M.xmlrpc_request_async(method, params, callback)
    async.run(function()
        local result = xmlrpc_request(method, params)
        callback(result)
    end)
end

--- Asynchronously fetch a list of functions from IDA.
-- @param callback function The callback with a newline-separated string of functions or nil
function M.list_functions(callback)
    M.xmlrpc_request_async('list_functions', {}, callback)
end

--- Asynchronously decompile a function.
-- @param func_name string The function name
-- @param callback function Called with decompiled code or nil
function M.decompile_function(func_name, callback)
    M.xmlrpc_request_async('decompile_function', { func_name, "" }, callback)
end

--- Asynchronously disassemble a function.
-- @param func_name string The function name
-- @param callback function Called with assembly code or nil
function M.disassemble_function(func_name, callback)
    M.xmlrpc_request_async('disassemble_function', { func_name, "" }, callback)
end

--- Asynchronously get a filesystem path associated with a function.
-- @param func_name string The function name
-- @param callback function Called with the path or nil
function M.get_path(func_name, callback)
    M.xmlrpc_request_async('get_path', { func_name }, callback)
end

return M
