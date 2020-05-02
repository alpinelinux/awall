--[[
Host address resolver for Alpine Wall
Copyright (C) 2012-2020 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}

local util = require('awall.util')
local listpairs = util.listpairs


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

function M.resolve(list, context, network)
   local res = {}

   for _, host in listpairs(list) do
      local family = getfamily(host, context)
      local entry

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

	 entry = dnscache[host]

      elseif not network and host:find('/') then
	 context:error('Network address not allowed: '..host)

      else entry = {{family, host}} end

      util.extend(res, entry)
   end

   return ipairs(res)
end

function M.resolveunique(list, families, context)
   local res = {}
   for _, addr in M.resolve(list, self) do
      local family = addr[1]
      if util.contains(families, family) then
	 if res[family] then context:error('Address must be unique') end
	 res[family] = addr[2]
      end
   end
   for _, family in listpairs(families) do
      if not res[family] then
	 context:error('No address provided for family '..family)
      end
   end
   return res
end

return M
