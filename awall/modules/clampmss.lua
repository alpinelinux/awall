--[[
TCP MSS clamping module for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')


local ClampMSSRule = model.class(model.Rule)

function ClampMSSRule:table() return 'mangle' end

function ClampMSSRule:servoptfrags()
   return {{opts='-p tcp --tcp-flags SYN,RST SYN'}}
end

function ClampMSSRule:target()
   return 'TCPMSS --'..(self.mss and 'set-mss '..self.mss or 'clamp-mss-to-pmtu')
end


return {export={['clamp-mss']={class=ClampMSSRule, before='tproxy'}}}
