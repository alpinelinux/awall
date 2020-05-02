--[[
Host address resolver for Alpine Wall
Copyright (C) 2012-2020 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}

local util = require('awall.util')


local familypatterns = {
   inet='%d[%.%d/]+', inet6='[:%x/]+', domain='[%a-][%.%w-]*'
}

local function getfamily(addr, context)
   for k, v in pairs(familypatterns) do
      if addr:match('^'..v..'$') then return k end
   end
   context:error('Malformed host specification: '..addr)
end

local dnscache = {}

function M.resolve(host, context, network)
   local family = getfamily(host, context)
   if family == 'domain' then

      if not dnscache[host] then
	 dnscache[host] = {}
	 for family, rtype in pairs{inet='A', inet6='AAAA'} do
	    local answer
	    for rec in io.popen('drill '..host..' '..rtype):lines() do
	       if answer then
		  if rec == '' then break end
		  local addr = rec:match(
		     '^'..familypatterns.domain..'%s+%d+%s+IN%s+'..rtype..
			'%s+(.+)'
		  )
		  if addr then
		     assert(getfamily(addr, context) == family)
		     table.insert(dnscache[host], {family, addr})
		  end
	       elseif rec == ';; ANSWER SECTION:' then answer = true end
	    end
	 end
	 if not dnscache[host][1] then
	    context:error('Invalid host name: '..host)
	 end
	 table.sort(dnscache[host], function(a, b) return a[2] < b[2] end)
      end

      return dnscache[host]
   end

   if not network and host:find('/') then
      context:error('Network address not allowed: '..host)
   end

   return {{family, host}}
end

function M.resolvelist(list, context, network)
   local res = {}
   for _, host in util.listpairs(list) do
      util.extend(res, M.resolve(host, context, network))
   end
   return ipairs(res)
end


return M
