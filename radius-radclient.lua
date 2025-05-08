-- Author : Alexander Petrossian paf@yandex.ru
-- Copyright 2024,2025
--
-- Adding the Lua script in Wireshark
-- windows: %APPDATA%\Wireshark\plugins
-- linux: ~/.local/lib/wireshark/plugins

--luarocks install mobdebug
--package.path = package.path .. ';//Users/paf/.luarocks/share/lua/5.4/?.lua'
--package.cpath = package.cpath .. ';/Users/paf/.luarocks/lib/lua/5.4/?.so'
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
	local python = root:add(field_python):set_text('# Python frame ' .. pinfo.number)

	local fields = { all_field_infos() }

	local code
	for _, i in ipairs(fields) do
		local n = i.name
		if n:find('^radius') and not i.generated then
			if n == 'radius.code' then
				code = i.value
			else
				if n == 'radius.authenticator' then
					local subfield = subfield_command:add(field_detail)
					subfield:set_text('CHAP-Challenge=' .. tostring(i.value) .. ',\\')
					local subfield_python = python:add(field_detail)
					subfield_python:set_text("req = srv.CreateAcctPacket(authenticator=int('" .. tostring(i.value) .. "', 16).to_bytes(16, 'big'))") -- TODO python ignores authenticator some reason
				else
					--if n:find('^radius.%u') then
						n = n:gsub("^radius.", ""):gsub("_", "-")
						if n ~= "CHAP-Ident"
								and n ~= "CHAP-String"
								and n ~= 'Event-Timestamp'
								and n ~= 'id'
								and n ~= 'length'
								and n ~= 'avp'
								and n ~= 'avp.type'
								and n ~= 'avp.length'
								and n ~= 'req'
								and n ~= 'radius'
								and not n:find('^avp.vendor')
								and not n:find('^authenticator')
						then
							local subfield = subfield_command:add(field_detail)
							subfield:set_text('"' .. n .. "='" .. tostring(i.value) .. "'" .. '",\\')
							local subfield_python = python:add(field_detail)
							subfield_python:set_text("req.AddAttribute('" .. n .. "', '" .. tostring(i.value) .. "')")
						end
					--end
				end
			end
		end
	end
	local subfield = subfield_command:add(field_detail)
	local cmd = code == 1 and 'auth' or 'acct'
	subfield:set_text('| radclient -x $endpoint ' .. cmd .. ' $secret')
end


