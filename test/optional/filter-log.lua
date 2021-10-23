--[[
Filter log test cases for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


json = require('cjson')

res = {}

for _, log in ipairs{
	'', false, true, 'dual', 'mirror', 'none', 'ulog', 'zero'
} do
	for _, action in ipairs{false, 'drop', 'pass'} do
		if log == '' then log = nil end
		table.insert(res, {log=log, action=action or nil})
	end
end

print(json.encode{filter=res})

-- vim: ts=4
