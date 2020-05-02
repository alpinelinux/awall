--[[
Address family module for Alpine Wall
Copyright (C) 2012-2020 Kaarle Ritvanen
See LICENSE file for license details
]]--

local M = {
   ACTIVE={},
   ALL={},
   PATTERNS={domain='[%a-][%.%w-]*', inet='%d[%.%d/-]+', inet6='[:%x/-]+'}
}

local stat = require('posix').stat

for family, procfile in pairs{inet='raw', inet6='raw6'} do
   table.insert(M.ALL, family)
   if stat('/proc/net/'..procfile) then table.insert(M.ACTIVE, family) end
end

function M.identify(addr, context)
   for k, v in pairs(M.PATTERNS) do
      if addr:match('^'..v..'$') then return k end
   end
   context:error('Malformed host specification: '..addr)
end

return M
