--[[
IPSet-based masquerading module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
See LICENSE file for license details
]]--


module(..., package.seeall)

-- TODO configuration of the ipset via JSON config
export = {
   ['%masquerade']={
      rules={
	 {
	    family='inet',
	    table='nat',
	    chain='POSTROUTING',
	    opts='-m set --match-set awall-masquerade src',
	    target='awall-masquerade'
	 },
	 {
	    family='inet',
	    table='nat',
	    chain='awall-masquerade',
	    opts='-m set ! --match-set awall-masquerade dst',
	    target='MASQUERADE'
	 }
      },
      after='snat'
   }
}
