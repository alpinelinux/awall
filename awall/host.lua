--[[
Host address resolver for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}

local family = require('awall.family')
local identify = family.identify

local util = require('awall.util')
local listpairs = util.listpairs


local dnscache = {}

function M.resolve(list, context, allow)
	local res = {}

	for _, host in listpairs(list) do
		local hfamily = identify(host, context)
		local entry

		if hfamily == 'domain' then

			if not dnscache[host] then
				dnscache[host] = {}
				for rfamily, rtype in pairs{inet='A', inet6='AAAA'} do
					local answer
					for rec in io.popen('drill '..host..' '..rtype):lines() do
						if answer then
							if rec == '' then break end
							local addr = rec:match(
								'^'..family.DOMAIN_PATTERN..'%s+%d+%s+IN%s+'..
								rtype..'%s+(.+)'
							)
							if addr then
								assert(identify(addr, context) == rfamily)
								table.insert(dnscache[host], {rfamily, addr})
							end
						elseif rec == ';; ANSWER SECTION:' then
							answer = true
						end
					end
				end
				if not dnscache[host][1] then
					context:error('Invalid host name: '..host)
				end
				table.sort(
					dnscache[host], function(a, b) return a[2] < b[2] end
				)
			end

			entry = dnscache[host]

		else
			if not allow then allow = {} end
			for k, v in pairs{
				network={'/', 'Network address'}, range={'-', 'Address range'}
			} do
				if not allow[k] and host:find(v[1]) then
					context:error(v[2]..' not allowed: '..host)
				end
			end
			entry = {{hfamily, host}}
		end

		util.extend(res, entry)
	end

	return ipairs(res)
end

function M.resolveunique(list, families, context)
	local res = {}
	for _, addr in M.resolve(list, context, {range=true}) do
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

-- vim: ts=4
