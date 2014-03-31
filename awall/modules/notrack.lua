--[[
Connection tracking bypass module for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


module(..., package.seeall)

require 'awall.model'

local model = awall.model


local NoTrackRule = model.class(model.Rule)

function NoTrackRule:table() return 'raw' end

function NoTrackRule:target()
   return model.Rule.target(self) or 'CT --notrack'
end


export = {['no-track']={class=NoTrackRule}}
