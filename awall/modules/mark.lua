--[[
Packet marking module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'

local model = awall.model


local MarkRule = model.class(model.ForwardOnlyRule)

function MarkRule:table() return 'mangle' end

function MarkRule:target()
   if not self.mark then self:error('Mark not specified') end
   return 'MARK --set-mark '..self.mark
end


classes = {{'mark', MarkRule}}

defrules = {}
