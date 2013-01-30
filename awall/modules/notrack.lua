--[[
Connection tracking bypass module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'

local model = awall.model


local NoTrackRule = model.class(model.Rule)

function NoTrackRule:table() return 'raw' end

function NoTrackRule:target()
   if self.action then return model.Rule.target(self) end
   return 'CT --notrack'
end


export = {['no-track']={class=NoTrackRule}}
