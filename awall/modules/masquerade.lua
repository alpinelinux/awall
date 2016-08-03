--[[
IPSet-based masquerading module for Alpine Wall
Copyright (C) 2012-2016 Kaarle Ritvanen
See LICENSE file for license details
]]--


-- TODO configuration of the ipset via JSON config
return {
   export={
      ['%masquerade']={
	 rules={
	    {
	       family='inet',
	       table='nat',
	       chain='POSTROUTING',
	       match='-m set --match-set awall-masquerade src',
	       target='awall-masquerade'
	    },
	    {
	       family='inet',
	       table='nat',
	       chain='awall-masquerade',
	       match='-m set ! --match-set awall-masquerade dst',
	       target='MASQUERADE'
	    }
	 },
	 after='snat'
      }
   }
}
