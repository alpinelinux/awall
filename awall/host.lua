--[[
Host address resolver for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


local familypatterns = {inet='%d[%.%d/]+',
			inet6='[:%x/]+',
			domain='[%a-][%.%w-]*'}

local function getfamily(addr, context)
   for k, v in pairs(familypatterns) do
      if addr:match('^'..v..'$') then return k end
   end
   context:error('Malformed host specification: '..addr)
end

local dnscache = {}

return function(host, context)
   local family = getfamily(host, context)
   if family == 'domain' then

      if not dnscache[host] then
	 dnscache[host] = {}
	 for rec in io.popen('dig -t ANY '..host):lines() do
	    local name, rtype, addr =
	       rec:match(
		  '^('..familypatterns.domain..')%s+%d+%s+IN%s+(A+)%s+(.+)'
	       )

	    if name and name:sub(1, host:len() + 1) == host..'.' then
	       if rtype == 'A' then family = 'inet'
	       elseif rtype == 'AAAA' then family = 'inet6'
	       else family = nil end

	       if family then
		  assert(getfamily(addr, context) == family)
		  table.insert(dnscache[host], {family, addr})
	       end
	    end
	 end
	 if not dnscache[host][1] then
	    context:error('Invalid host name: '..host)
	 end
	 table.sort(dnscache[host], function(a, b) return a[2] < b[2] end)
      end

      return dnscache[host]
   end

   return {{family, host}}
end
