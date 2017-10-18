--[[
Address match test cases for Alpine Wall
Copyright (C) 2012-2017 Kaarle Ritvanen
See LICENSE file for license details
]]--


util = require('awall.util')
json = require('cjson')

res = {}

saddr = '10.0.0.1'
daddr = '172.16.0.0/16'

for _, izone in ipairs{false, 'A', 'B', {'B', 'C'}} do
   for _, ozone in ipairs{false, 'B'} do
      for _, src in ipairs{false, saddr, {saddr, '10.0.0.2'}} do
	 for _, dest in ipairs{false, daddr, {daddr, '172.16.2.0/16'}} do
	    for _, log in ipairs{false, true} do
	       for _, action in ipairs{false, 'pass'} do
		  table.insert(
		     res,
		     {
			['in']=izone or nil,
			out=ozone or nil,
			src=src or nil,
			dest=dest or nil,
			log=log or nil,
			action=action or nil
		     }
		  )
	       end
	    end
	 end
      end
   end
end

print(json.encode{filter=res})
