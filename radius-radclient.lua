-- Author : Alexander Petrossian paf@yandex.ru
-- Copyright 2024
--
-- Adding the Lua script in Wireshark
-- 1) Open init.lua in the Wireshark installation directory for editing. You will need Admin privileges on Windows Vista and 7.
--
-- 2) Add the following lines to init.lua (at the very end):
--
-- 3) PAF_SCRIPT_PATH="C:\\opt\\"
-- 	dofile(PAF_SCRIPT_PATH.."tptf.lua")

--	Debug in ZeroBrane Studio  http://studio.zerobrane.com/
--debug = require("debug")
--require("mobdebug").start()

local radclient_proto = Proto("radclient","RADIUS Client")
local field_desc = ProtoField.string("radclient.command")
radclient_proto.fields = { field_desc }
register_postdissector(radclient_proto)

local avp = Field.new("radius.avp")

local code2command = {
	[1] = "auth",
}

function radclient_proto.dissector(tvb,pinfo,tree)
	local root = tree:add(radclient_proto):set_generated()
	local field = root:add(field_desc):set_text('echo \\')

	local fields = { all_field_infos() }

	local code
	for _, i in ipairs(fields) do
		local n = i.name
		if n:find('^radius') then
			if n == 'radius.code' then
				code = i.value
			else
				if n:find('^radius.%u') then
					n = n:gsub("^radius.", ""):gsub("_", "-")
					if n ~= "CHAP-Ident" and n ~= "CHAP-String" and n ~= 'Event-Timestamp' then
						local subfield = field:add(field_desc)
						subfield:set_text('"' .. n .. "='" .. tostring(i.value) .. "'" .. '",\\')
					end
				end
			end
		end
	end
	local subfield = field:add(field_desc)
	local command = code == 1 and 'auth' or 'acct'
	subfield:set_text('| radclient -x $endpoint ' .. command .. ' $secret')
end


