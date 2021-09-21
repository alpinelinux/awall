--[[
Address family module for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--

local M = {ACTIVE={}, ALL={}, DOMAIN_PATTERN='[%.%w-]+'}

local stat = require('posix').stat

for family, procfile in pairs{inet='raw', inet6='raw6'} do
   table.insert(M.ALL, family)
   if stat('/proc/net/'..procfile) then table.insert(M.ACTIVE, family) end
end

function M.identify(addr, context)
   for _, pattern in ipairs{
      {'inet', '[%.%d/-]+'}, {'domain', M.DOMAIN_PATTERN}, {'inet6', '[:%x/-]+'}
   } do
      if addr:match('^'..pattern[2]..'$') then return pattern[1] end
   end
   context:error('Malformed host specification: '..addr)
end

return M
