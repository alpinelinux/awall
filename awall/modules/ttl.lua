--[[
TTL adjustment module for Alpine Wall
Copyright (C) 2012-2016 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')


local TTLRule = model.class(model.Rule)

function TTLRule:trulefilter(rule) return rule.family == 'inet' end

function TTLRule:table() return 'mangle' end

function TTLRule:target()
   if not self.ttl then self:error('TTL not specified') end

   if type(self.ttl) == 'string' then
      if self.ttl:sub(1, 1) == '+' then
         return 'TTL --ttl-inc '..self.ttl:sub(2, -1)
      else self.ttl = tonumber(self.ttl) end
   end
   if type(self.ttl) ~= 'number' then
      self:error('Invalid TTL specification')
   end

   return 'TTL --ttl-'..(self.ttl < 0 and 'dec' or 'set')..' '..
      math.abs(self.ttl)
end

return {export={ttl={class=TTLRule}}}
