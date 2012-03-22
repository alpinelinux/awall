--[[
Ipset file dumper for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.object'

IPSet = awall.object.class(awall.object.Object)

function IPSet:init(config) self.config = config end

function IPSet:commands()
   local res = {}
   if self.config then
      for name, params in pairs(self.config) do
	 if not params.type then error('Type not defined for set '..name) end
	 local line = 'create '..name..' '..params.type
	 if params.family then line = line..' family '..params.family end
	 table.insert(res, line..'\n')
      end
   end
   return res
end

function IPSet:create()
   for i, line in ipairs(self:commands()) do
      local pid, stdin = lpc.run('ipset', '-!', 'restore')
      stdin:write(line)
      stdin:close()
      if lpc.wait(pid) ~= 0 then
	 io.stderr:write('ipset command failed: '..line)
      end
   end
end

function IPSet:dump(ipsfile)
   local file = io.output(ipsfile)
   for i, line in ipairs(self:commands()) do file:write(line) end
   file:close()
end
