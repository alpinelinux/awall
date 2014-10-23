--[[
Class model with inheritance and morphing support for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--

local Object

local function class(base)
   local cls = {}

   function cls.super(obj)
      return setmetatable(
	 {},
	 {
	    __index=function(t, k)
	       local v = base[k]
	       if type(v) ~= 'function' then return v end
	       return function(...)
		  local arg = {...}
		  arg[1] = obj
		  return v(table.unpack(arg))
	       end
	    end
	 }
      )
   end

   function cls:morph(...)
      setmetatable(self, {__index = cls})
      self:init(...)
      return self
   end

   local mt = {__call=function(self, ...) return cls.morph({}, ...) end}

   if not base and Object then base = Object end
   if base then mt.__index = base end

   return setmetatable(cls, mt)
end

Object = class()
function Object:init(...) end

return class
