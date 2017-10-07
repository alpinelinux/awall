util = require('awall.util')
json = require('cjson')

res = {}

function add(limit_type, base)
   for _, count in ipairs{1, 30} do
      for _, limit in ipairs{
         count, {count=count, log=false}, {count=count, log='none'}
      } do
         for _, log in ipairs{false, true, 'none'} do
            for _, action in ipairs{false, 'pass'} do
	       if not (count == 30 and log and action) then
	          table.insert(
	             res,
		     util.update(
		        util.copy(base or {}),
		        {
		           [limit_type..'-limit']=limit,
		           log=log or nil,
		           action=action or nil
		        }
		     )
                  )
               end
	    end
	 end
      end
   end
end

add('conn', {out='B'})
add('flow')
add('flow', {['in']='A', out='_fw', ['no-track']=true})

for _, measure in ipairs{'conn', 'flow'} do
   for _, addr in ipairs{'src', 'dest'} do
      table.insert(
         res, {['update-limit']={name='foo', measure=measure, addr=addr}}
      )
   end
end

print(json.encode{filter=res})
