--[[
Transparent proxy module for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')
local combinations = require('awall.optfrag').combinations

local util = require('awall.util')
local contains = util.contains
local list = util.list
local listpairs = util.listpairs


local TProxyRule = model.class(model.Rule)

function TProxyRule:init(...)
   TProxyRule.super(self):init(...)

   if not self['in'] then self:error('Ingress zone must be specified') end
   if contains(list(self['in']), model.fwzone) then
      self:error('Transparent proxy cannot be used for firewall zone')
   end
   if self.out then self:error('Egress zone cannot be specified') end

   if not self.service then self:error('Service must be defined') end
   for i, serv in listpairs(self.service) do
      for i, sdef in listpairs(serv) do
	 if not contains({6, 'tcp', 17, 'udp'}, sdef.proto) then
	    self:error('Transparent proxy not available for protocol '..sdef.proto)
	 end
      end
   end
end

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
	 {chain='PREROUTING', opts='-m socket', target='divert'}
      )
      return combinations(
	 {{family='inet'}, {family='inet6'}},
	 {{table='mangle'}},
	 ofrags
      )
   end
end


return {
   export={
      tproxy={class=TProxyRule, before='%mark-restore'},
      ['%tproxy-divert']={rules=divert, before='tproxy'}
   }
}
