--[[
User error handling for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--

module(..., package.seeall)

local prefix = 'awall user error: '

function raise(msg) error(prefix..msg) end

function call(f, ...)
   return xpcall(
      function() f(unpack(arg)) end,
      function(msg)
	 local si, ei = string.find(msg, prefix, 1, true)
   	 if si then msg = 'awall: '..string.sub(msg, ei + 1, -1) end
   	 io.stderr:write(msg..'\n')
   	 if not si then io.stderr:write(debug.traceback()..'\n') end
      end
   )
end
