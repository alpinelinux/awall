--[[
Transparent proxy module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
See LICENSE file for license details
]]--


module(..., package.seeall)

local class = require('awall.model').class
local combinations = require('awall.optfrag').combinations
local util = require('awall.util')

local MarkRule = require('awall').loadclass('mark')

local TProxyRule = class(MarkRule)

function TProxyRule:target()
   local port = self['to-port'] or 0
   return 'TPROXY --tproxy-mark '..self.mark..' --on-port '..port
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
