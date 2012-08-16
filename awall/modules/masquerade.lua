--[[
IPSet-based masquerading module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

-- TODO configuration of the ipset via JSON config
defrules = {['post-snat']={{family='inet', table='nat',
			    chain='POSTROUTING',
			    opts='-m set --match-set awall-masquerade src',
			    target='awall-masquerade'},
			   {family='inet', table='nat',
			    chain='awall-masquerade',
			    opts='-m set ! --match-set awall-masquerade dst',
			    target='MASQUERADE'}}}
