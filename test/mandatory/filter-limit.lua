util = require('awall.util')
json = require('cjson')

res = {}

function add(limit_type, filter)

   for _, high_rate in ipairs{false, true} do

      local function add_limit(limit)
         for _, log in ipairs{false, true, 'none'} do
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

      local count = high_rate and 30 or 1
      add_limit(count)

      for _, log in ipairs{true, false, 'none'} do
	 local limit = {count=count}
	 if log ~= true then limit.log = log end

         add_limit(limit)

	 if not high_rate then
	    limit.name = 'foo'

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

add('conn', {out='B'})
add('flow')
add('flow', {['in']='A', out='_fw', ['no-track']=true})

table.insert(res, {['update-limit']='foo'})

for _, measure in ipairs{'conn', 'flow'} do
   for _, addr in ipairs{'src', 'dest'} do
      table.insert(
         res, {['update-limit']={name='foo', measure=measure, addr=addr}}
      )
   end
end

print(json.encode{filter=res})
