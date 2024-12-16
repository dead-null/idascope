-- lua/telescope_ida/xml_parser.lua
--
-- Simple XML-RPC response parser for IDAScope.
-- Extracts parameters and fault information from XML-RPC responses.

local M = {}

--- Trim whitespace from a string.
-- @param s string The input string
-- @return string The trimmed string
local function trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

--- Parse an XML-RPC response string.
-- Returns a table with either a `fault` or `params`.
-- @param xml_str string The XML response
-- @return table A table with `fault` or `params`
function M.parse_response(xml_str)
    local response = {}
    local fault = xml_str:match("<fault>%s*(.-)%s*</fault>")
    if fault then
        local fault_string = fault:match("<name>faultString</name>%s*<value>%s*<string>(.-)</string>%s*</value>")
        local fault_code = fault:match("<name>faultCode</name>%s*<value>%s*<int>(%d+)</int>%s*</value>")
        response.fault = {
            code = tonumber(fault_code),
            string = fault_string
        }
        return response
    end

    local params = {}
    for param in xml_str:gmatch("<param>%s*(.-)%s*</param>") do
        local value = param:match("<value>%s*<string>(.-)</string>%s*</value>")
        if not value then
            value = param:match("<value>%s*<base64>(.-)</base64>%s*</value>")
        end
        if value then
            table.insert(params, trim(value))
        else
            table.insert(params, "")
        end
    end

    response.params = params
    return response
end

return M
