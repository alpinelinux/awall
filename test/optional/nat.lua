--[[
NAT test cases for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


util = require('awall.util')
json = require('cjson')

res = {}

for _, mode in ipairs{{'dnat', {['in']='A'}}, {'snat', {out='B'}}} do
	res[mode[1]] = {}

	local function add(params)
		table.insert(res[mode[1]], util.update(util.copy(mode[2]), params))
	end

	local function add_exclude(family)
		add{family=family, service='ssh', action='exclude'}
	end

	local function add_include(params)
		for _, port in ipairs{false, 7890, '1234-5678'} do
			params.service = 'http'
			params['to-port'] = port or nil
			add(params)
		end
	end

	add_exclude()
	add_include{}

	for _, addr in ipairs{
		{'inet', '10.2.3.100-10.2.3.200'},
		{'inet6', 'fc00:600d::cafe'},
		{{'inet', 'inet6'}, {'10.1.2.3', 'fc00:dead::beef-fc00:dead::ca1f'}}
	} do
		add_exclude(addr[1])
		add_include{family=addr[1]}
		add_include{['to-addr']=addr[2]}
		add_include{family=addr[1], ['to-addr']=addr[2]}
	end
end

print(json.encode(res))

-- vim: ts=4
