--[[
Filter limit test cases for Alpine Wall
Copyright (C) 2012-2017 Kaarle Ritvanen
See LICENSE file for license details
]]--


util = require('awall.util')
json = require('cjson')

res = {}

function add(limit_type, filter)

   local logopts = {false, true, 'mirror', 'none', 'ulog'}

   for _, high_rate in ipairs{false, true} do

      local function add_limit(limit)
         for _, log in ipairs(logopts) do
            for _, action in ipairs{false, 'pass'} do
               if not (high_rate and log and action) then
	          table.insert(
	             res,
	             util.update(
	                {
		           [limit_type..'-limit']=util.copy(limit),
		           log=log or nil,
		           action=action or nil
	                },
		        filter or {}
	             )
                  )
	       end
            end
         end
      end

      local count = high_rate and 150 or nil
      add_limit(count or 1)

      for _, interval in ipairs{false, 5} do
         for _, log in ipairs(logopts) do
	    local limit = {count=count, interval=interval or nil}
	    if log ~= true then limit.log = log end

            add_limit(limit)

	    if not high_rate then
	       for _, name in ipairs{'A', 'C'} do
	          limit.name = name

	          for _, addr in ipairs{false, 'dest'} do
	             limit.addr = addr or nil

	             limit.update = nil
	             add_limit(limit)

	             limit.update = false
	             add_limit(limit)
	          end
	       end
	    end
	 end
      end
   end
end

add('conn', {out='B'})
add('conn', {['in']='_fw', out='B'})
add('flow')
add('flow', {['in']='A', out='_fw', ['no-track']=true})

for _, name in ipairs{'A', 'B', 'C', 'D'} do
   table.insert(res, {['update-limit']=name})
end

function add_update_limit(name, measure)
   for _, addr in ipairs{'src', 'dest'} do
      table.insert(
         res, {['update-limit']={name=name, measure=measure, addr=addr}}
      )
   end
end

add_update_limit('A', 'conn')
add_update_limit('B', 'flow')

print(json.encode{filter=res})
