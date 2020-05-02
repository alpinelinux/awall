--[[
NAT test cases for Alpine Wall
Copyright (C) 2012-2020 Kaarle Ritvanen
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

   local function add_include(params)
      for _, port in ipairs{false, 7890, '1234-5678'} do
	 params.service = 'http'
	 params['to-port'] = port or nil
	 add(params)
      end
   end

   add{service='ssh', action='exclude'}
   add_include{}

   for _, addr in ipairs{'10.1.2.3', '10.2.3.100-10.2.3.200'} do
      add_include{['to-addr']=addr}
   end
end

print(json.encode(res))
