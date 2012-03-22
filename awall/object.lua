--[[
Class model with inheritance and morphing support for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

function class(base)
   local cls = {}
   local mt = {__index = cls}

   if base then setmetatable(cls, {__index = base}) end

   function cls.new(...)
      local inst = arg[1] and arg[1] or {}
      cls.morph(inst)
      return inst
   end

   function cls:morph(...)
      setmetatable(self, mt)
      self:init(unpack(arg))
   end

   return cls
end

Object = class()

function Object:init(...) end
