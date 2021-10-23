--[[
Ipset file dumper for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local util = require('awall.util')


local IPSet = require('awall.class')()

function IPSet:init(config) self.config = config or {} end

function IPSet:dumpfile(name, ipsfile)
	ipsfile:write('# ipset '..name..'\n')
	ipsfile:write(table.concat(self.config[name].options, ' '))
	ipsfile:write('\n')
end

function IPSet:create()
	for name, ipset in pairs(self.config) do
		if util.execute(
			'ipset', '-!', 'create', name, table.unpack(ipset.options)
		) ~= 0 then
			util.printmsg('ipset creation failed: '..name)
		end
	end
end

function IPSet:print()
	for _, name in util.sortedkeys(self.config) do
		self:dumpfile(name, io.output())
		io.write('\n')
	end
end

function IPSet:dump(prefix)
	for name, ipset in pairs(self.config) do
		local fname = prefix..name
		local file = io.open(fname)
		if not file then
			file = io.open(fname, 'w')
			self:dumpfile(name, file)
		end
	file:close()
	end
end

return IPSet

-- vim: ts=4
