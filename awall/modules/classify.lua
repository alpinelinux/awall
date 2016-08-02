--[[
Packet classification module for Alpine Wall
Copyright (C) 2012-2016 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')
local extend = require('awall.util').extend


local ClassificationRule = model.class(model.Rule)

function ClassificationRule:init(...)
   ClassificationRule.super(self):init(...)
   if not self.class then self:error('Class not specified') end
end

function ClassificationRule:table() return 'mangle' end

function ClassificationRule:target()
   return 'DSCP --set-dscp-class '..self.class
end

function ClassificationRule:extratrules(rules)
   return not self.reverse and self:extrarules(
      'reply', 'classify', {attrs='class', update={reverse=true}}
   )
end

return {export={classify={class=ClassificationRule}}}
