--[[
User error handling for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}

local prefix = 'awall user error: '

function M.raise(msg) error(prefix..msg) end

function M.call(f, ...)
   local arg = {...}
   return xpcall(
      function() f(table.unpack(arg)) end,
      function(msg)
	 local si, ei = msg:find(prefix, 1, true)
	 if si then msg = 'awall: '..msg:sub(ei + 1, -1) end
   	 io.stderr:write(msg..'\n')
   	 if not si then io.stderr:write(debug.traceback()..'\n') end
      end
   )
end

return M
