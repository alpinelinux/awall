--[[
Connection tracking bypass module for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')
local schema = require('awall.schema')


local NoTrackRule = model.class(model.Rule)

function NoTrackRule:table() return 'raw' end

function NoTrackRule:target()
   return NoTrackRule.super(self):target() or 'CT --notrack'
end


return {export={['no-track']={schema=schema.Rule(), class=NoTrackRule}}}
