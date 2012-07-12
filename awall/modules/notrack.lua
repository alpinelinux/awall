--[[
Connection tracking bypass module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'
require 'awall.util'

local model = awall.model


local NoTrackRule = model.class(model.Rule)

function NoTrackRule:init(...)
   model.Rule.init(self, unpack(arg))
   for i, dir in ipairs({'in', 'out'}) do
      if awall.util.contains(self[dir], model.fwzone) then
	 self:error('Connection tracking bypass rules not allowed for firewall zone')
      end
   end
end

function NoTrackRule:defaultzones() return {nil} end

function NoTrackRule:checkzoneoptfrag(ofrag)
   if ofrag.out then
      self:error('Cannot specify outbound interface for connection tracking bypass rule')
   end
end

function NoTrackRule:table() return 'raw' end

function NoTrackRule:chain() return 'PREROUTING' end

function NoTrackRule:target()
   if self.action then return model.Rule.target(self) end
   return 'NOTRACK'
end


classes = {{'notrack', NoTrackRule}}

defrules = {}
