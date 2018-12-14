--[[
Address family module for Alpine Wall
Copyright (C) 2012-2019 Kaarle Ritvanen
See LICENSE file for license details
]]--

local M = {ACTIVE={}, ALL={}}

local stat = require('posix').stat

for family, procfile in pairs{inet='raw', inet6='raw6'} do
   table.insert(M.ALL, family)
   if stat('/proc/net/'..procfile) then table.insert(M.ACTIVE, family) end
end

return M
