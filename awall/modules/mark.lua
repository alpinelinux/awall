--[[
Packet marking module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
See LICENSE file for license details
]]--


module(..., package.seeall)

local model = require('awall.model')
local class = model.class

local combinations = require('awall.optfrag').combinations

local util = require('awall.util')
local contains = util.contains
local list = util.list
local listpairs = util.listpairs


local MarkRule = class(model.Rule)

function MarkRule:init(...)
   model.Rule.init(self, unpack(arg))
   if not self.mark then self:error('Mark not specified') end
end

function MarkRule:table() return 'mangle' end

function MarkRule:target() return 'MARK --set-mark '..self.mark end


local RouteTrackRule = class(MarkRule)

function RouteTrackRule:target() return self:newchain('mark') end

function RouteTrackRule:servoptfrags()
   return combinations(
      MarkRule.servoptfrags(self),
      {{opts='-m mark --mark 0'}}
   )
end

function RouteTrackRule:extraoptfrags()
   return {{chain=self:target(), target=MarkRule.target(self)},
	   {chain=self:target(), target='CONNMARK --save-mark'}}
end


local TProxyRule = class(MarkRule)

function TProxyRule:init(...)
   MarkRule.init(self, unpack(arg))
   if not self['in'] then self:error('Ingress zone must be specified') end
   if contains(list(self['in']), model.fwzone) then
      self:error('Transparent proxy cannot be used for firewall zone')
   end
   if self.out then self:error('Egress zone cannot be specified') end
end

function TProxyRule:target() return self:newchain('tproxy') end

function TProxyRule:extraoptfrags()
   local res = {
      {
	 chain='PREROUTING',
	 opts='-m socket -m mark --mark '..self.mark,
	 target='ACCEPT',
	 position='prepend'
      },
      {chain=self:target(), target='CONNMARK --set-mark '..self.mark},
   }

   local popts = {}
   for i, serv in listpairs(self.service) do
      for i, sdef in listpairs(serv) do
	 if not contains({6, 'tcp', 17, 'udp'}, sdef.proto) then
	    self:error('Transparent proxy not available for protocol '..sdef.proto)
	 end
	 popts[sdef.proto] = {opts='-p '..sdef.proto}
      end
   end

   local port = self['to-port'] or 0
   util.extend(
      res,
      combinations(
	 util.values(popts),
	 {
	    {
	       chain=self:target(),
	       target='TPROXY --tproxy-mark '..self.mark..' --on-port '..port
	    }
	 }
      )
   )

   return res
end


local function restoremark(config)
   local chopts = {}
   if list(config['route-track'])[1] then
      chopts = {{chain='OUTPUT'}, {chain='PREROUTING'}}
   elseif list(config['tproxy'])[1] then chopts = {{chain='PREROUTING'}} end

   return combinations(
      {{family='inet'}, {family='inet6'}},
      chopts,
      {
	 {
	    table='mangle',
	    opts='-m connmark ! --mark 0',
	    target='CONNMARK --restore-mark',
	    position='prepend'
	 }
      }
   )
end

export = {
   mark={class=MarkRule},
   ['route-track']={class=RouteTrackRule, before='mark'},
   tproxy={class=TProxyRule, before='route-track'},
   ['%mark-restore']={rules=restoremark, after='tproxy'}
}
