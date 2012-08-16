--[[
Connection tracking bypass module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'

local model = awall.model


local NoTrackRule = model.class(model.ForwardOnlyRule)

function NoTrackRule:table() return 'raw' end

function NoTrackRule:target()
   if self.action then return model.ForwardOnlyRule.target(self) end
   return 'NOTRACK'
end


classes = {{'no-track', NoTrackRule}}
