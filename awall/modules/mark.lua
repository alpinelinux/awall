--[[
Packet marking module for Alpine Wall
Copyright (C) 2012-2017 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')
local class = model.class

local combinations = require('awall.optfrag').combinations
local util = require('awall.util')


local MarkRule = class(model.Rule)

function MarkRule:init(...)
   MarkRule.super(self):init(...)
   if not self.mark then self:error('Mark not specified') end
end

function MarkRule:table() return 'mangle' end

function MarkRule:target() return 'MARK --set-mark '..self.mark end


local RouteTrackRule = class(MarkRule)

function RouteTrackRule:mangleoptfrags(ofrags)
   local markchain = self:uniqueid('mark')
   return util.extend(
      self:settarget(
	 combinations(ofrags, {{match='-m mark --mark 0'}}), markchain
      ),
      {{chain=markchain}, {chain=markchain, target='CONNMARK --save-mark'}}
   )
end


local function restoremark(config)
   if util.list(config['route-track'])[1] then
      return combinations(
	 {{family='inet'}, {family='inet6'}},
	 {{chain='OUTPUT'}, {chain='PREROUTING'}},
	 {
	    {
	       table='mangle',
	       match='-m connmark ! --mark 0',
	       target='CONNMARK --restore-mark'
	    }
	 }
      )
   end
end


return {
   export={
      mark={class=MarkRule},
      ['route-track']={class=RouteTrackRule, before='mark'},
      ['%mark-restore']={rules=restoremark, before='route-track'}
   }
}
