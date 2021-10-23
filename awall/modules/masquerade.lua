--[[
IPSet-based masquerading module for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
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
					target='masquerade'
				},
				{
					family='inet',
					table='nat',
					chain='masquerade',
					match='-m set ! --match-set awall-masquerade dst',
					target='MASQUERADE'
				}
			},
			after='snat'
		}
	}
}

-- vim: ts=4
