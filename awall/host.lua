--[[
Host address resolver for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

local familypatterns = {ip4='%d[%.%d/]+',
			ip6='[:%x/]+',
			domain='[%a-][%.%w-]*'}

local function getfamily(addr)
   for k, v in pairs(familypatterns) do
      if string.match(addr, '^'..v..'$') then return k end
   end
   error('Malformed host specification: '..addr)
end

local dnscache = {}

function resolve(host)
   local family = getfamily(host)
   if family == 'domain' then

      if not dnscache[host] then
	 dnscache[host] = {}
	 -- TODO use default server
	 for rec in io.popen('dig @8.8.8.8 '..host..' ANY'):lines() do
	    local name, rtype, addr =
	       string.match(rec, '^('..familypatterns.domain..')\t+%d+\t+IN\t+(A+)\t+(.+)')

	    if name and string.sub(name, 1, string.len(host) + 1) == host..'.' then
	       if rtype == 'A' then family = 'ip4'
	       elseif rtype == 'AAAA' then family = 'ip6'
	       else family = nil end

	       if family then
		  assert(getfamily(addr) == family)
		  table.insert(dnscache[host], {family, addr})
	       end
	    end
	 end
	 if not dnscache[host][1] then error('Invalid host name: '..host) end
      end

      return dnscache[host]
   end

   return {{family, host}}
end
