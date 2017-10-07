update = require('awall.util').update
json = require('cjson')

res = {}

function add(limit_type, base)
   for _, count in ipairs{1, 30} do
      for _, limit in ipairs{
         count,
	 {count=count},
	 {count=count, log=false},
	 {count=count, log='none'}
      } do
         for _, name in ipairs{
            false, type(limit) == 'table' and count == 1 and 'foo' or nil
         } do
	    for _, addr in ipairs{false, name and 'dest' or nil} do
	       for _, no_update in ipairs{false, name or nil} do
	          local upd
	          if no_update then upd = false end
                  for _, log in ipairs{false, true, 'none'} do
                     for _, action in ipairs{false, 'pass'} do
	                if not (count == 30 and log and action) then
	                   table.insert(
	                      res,
		              update(
		                 {
		                    [limit_type..'-limit']=type(limit) == 'table' and update(
			               {
				          name=name or nil,
					  addr=addr or nil,
					  update=upd
				       },
				       limit
		                    ) or limit,
		                    log=log or nil,
		                    action=action or nil
		                 },
		                 base or {}
		              )
                           )
		        end
		     end
	          end
               end
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
