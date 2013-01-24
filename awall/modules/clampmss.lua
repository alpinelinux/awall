--[[
TCP MSS clamping module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'

local model = awall.model


local ClampMSSRule = model.class(model.Rule)

function ClampMSSRule:table() return 'mangle' end

function ClampMSSRule:servoptfrags()
   return {{opts='-p tcp --tcp-flags SYN,RST SYN'}}
end

function ClampMSSRule:target()
   return 'TCPMSS --'..(self.mss and 'set-mss '..self.mss or 'clamp-mss-to-pmtu')
end


export = {['clamp-mss']={class=ClampMSSRule}}
