--[[
Transparent proxy module for Alpine Wall
Copyright (C) 2012-2020 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')

local optfrag = require('awall.optfrag')
local combinations = optfrag.combinations

local util = require('awall.util')
local list = util.list


local TProxyRule = model.class(model.Rule)

function TProxyRule:init(...)
   TProxyRule.super(self):init(...)

   if not self['in'] then self:error('Ingress zone must be specified') end
   if util.contains(list(self['in']), model.fwzone) then
      self:error('Transparent proxy cannot be used for firewall zone')
   end
   if self.out then self:error('Egress zone cannot be specified') end
end

function TProxyRule:porttrans() return true end

function TProxyRule:table() return 'mangle' end

function TProxyRule:target()
   local mark = self.root.variable['awall_tproxy_mark']
   local port = self['to-port'] or 0
   return 'TPROXY --tproxy-mark '..mark..' --on-port '..port
end


local function divert(config)
   if list(config.tproxy)[1] then
      local ofrags = combinations(
	 {{chain='divert'}},
	 {
	    {target='MARK --set-mark '..config.variable['awall_tproxy_mark']},
	    {target='ACCEPT'}
	 }
      )
      table.insert(
	 ofrags,
	 {chain='PREROUTING', match='-m socket', target='divert'}
      )
      return optfrag.expandfamilies(combinations({{table='mangle'}}, ofrags))
   end
end


return {
   export={
      tproxy={class=TProxyRule, before='%mark-restore'},
      ['%tproxy-divert']={rules=divert, before='tproxy'}
   }
}
