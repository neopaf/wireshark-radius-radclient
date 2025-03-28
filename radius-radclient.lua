-- Author : Alexander Petrossian paf@yandex.ru
-- Copyright 2024,2025
--
-- Adding the Lua script in Wireshark
-- windows: %APPDATA%\Wireshark\plugins
-- linux: ~/.local/lib/wireshark/plugins

--	Debug in ZeroBrane Studio  http://studio.zerobrane.com/
--debug = require("debug")
--require("mobdebug").start()

local radclient_proto = Proto("radclient","RADIUS Client")
local field_command = ProtoField.string("radclient.command")
local field_python = ProtoField.string("radclient.python")
local field_detail = ProtoField.string("radius.detail")
radclient_proto.fields = { field_command, field_detail, field_python}
register_postdissector(radclient_proto)


function radclient_proto.dissector(tvb,pinfo,tree)
	local root = tree:add(radclient_proto):set_generated()
	local subfield_command = root:add(field_command):set_text('echo \\')
	local python = root:add(field_python):set_text('Python')

	local fields = { all_field_infos() }

	local code
	for _, i in ipairs(fields) do
		local n = i.name
		if n:find('^radius') then
			if n == 'radius.code' then
				code = i.value
			else
				if n == 'radius.authenticator' then
					local subfield = subfield_command:add(field_detail)
					subfield:set_text('CHAP-Challenge=' .. tostring(i.value) .. ',\\')
					local subfield_python = python:add(field_detail)
					subfield_python:set_text('avp["CHAP-Challenge"]="' .. tostring(i.value) .. '"')
				else
					if n:find('^radius.%u') then
						n = n:gsub("^radius.", ""):gsub("_", "-")
						if n ~= "CHAP-Ident" and n ~= "CHAP-String" and n ~= 'Event-Timestamp' then
							local subfield = subfield_command:add(field_detail)
							subfield:set_text('"' .. n .. "='" .. tostring(i.value) .. "'" .. '",\\')
							local subfield_python = python:add(field_detail)
							subfield_python:set_text('avp["' .. n .. '"]="' .. tostring(i.value) .. "'")
						end
					end
				end
			end
		end
	end
	local subfield = subfield_command:add(field_detail)
	local cmd = code == 1 and 'auth' or 'acct'
	subfield:set_text('| radclient -x $endpoint ' .. cmd .. ' $secret')
end


