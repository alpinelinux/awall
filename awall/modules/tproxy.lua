--[[
Transparent proxy module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

local class = require('awall.model').class
local combinations = require('awall.optfrag').combinations
local util = require('awall.util')

local MarkRule = require('awall').loadclass('mark')

local TProxyRule = class(MarkRule)

function TProxyRule:target()
   if not self['to-port'] then self:error('Proxy port not specified') end
   return 'TPROXY --tproxy-mark '..self.mark..' --on-port '..self['to-port']
end

function TProxyRule:mangleoptfrag(ofrag)
   local dof = util.copy(ofrag)
   dof.target = nil
   local res = combinations(
      {dof},
      {{opts='-m socket', target=self:newchain('divert')}}
   )
   table.insert(res, ofrag)
   return res
end

function TProxyRule:extraoptfrags()
   return combinations(
      {{chain=self:newchain('divert')}},
      {{target=MarkRule.target(self)}, {target='ACCEPT'}}
   )
end

export = {tproxy={class=TProxyRule, before={'clamp-mss', '%mark-rt'}}}
