--[[
Copyright 2012 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS-IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--]]

local logging = require('logging')
local Error = require('core').Error
local fs = require('fs')
local math = require('math')
local table = require('table')

local delta = 0
local delay = 0

local function gmtNow()
  return math.floor(virgo.gmtnow() + delta)
end

local function trim(s)
  return s:find'^%s*$' and '' or s:match'^%s*(.*%S)'
end

local function gmtRaw()
  return math.floor(virgo.gmtnow())
end

local function setDelta(_delta)
  delta = _delta
end

local function getDelta()
  return delta
end

--[[

This algorithm follows the NTP algorithm found here:

http://www.eecis.udel.edu/~mills/ntp/html/warp.html

T1 = agent departure timestamp
T2 = server receieved timestamp
T3 = server transmit timestamp
T4 = agent destination timestamp

]]--
local function timesync(T1, T2, T3, T4)
  if not T1 or not T2 or not T3 or not T4 then
    return Error:new('T1, T2, T3, or T4 was null. Failed to sync time.')
  end

  logging.debugf('time_sync data: T1 = %.0f T2 = %.0f T3 = %.0f T4 = %.0f', T1, T2, T3, T4)

  delta = ((T2 - T1) + (T3 - T4)) / 2
  delay = ((T4 - T1) + (T3 - T2))

  logging.infof('Setting time delta to %.0fms based on server time %.0fms', delta, T2)

  return
end

local function tableGetBoolean(tt, key, default)
  local value = tt[key] or default
  if type(value) == 'string' then
    if value:lower() == 'false' then
      return false
    end
  end
  if type(value) == 'number' then
    if value == 0 then
      return false
    end
  end
  return value
end

local function parseCSVLine (line,sep)
  local res = {}
  local pos = 1
  sep = sep or ','
  while true do
    local c = string.sub(line,pos,pos)
    if (c == "") then break end
    if (c == '"') then
      -- quoted value (ignore separator within)
      local txt = ""
      repeat
        local startp,endp = string.find(line,'^%b""',pos)
        txt = txt..string.sub(line,startp+1,endp-1)
        pos = endp + 1
        c = string.sub(line,pos,pos)
        if (c == '"') then txt = txt..'"' end
        -- check first char AFTER quoted string, if it is another
        -- quoted string without separator, then append it
        -- this is the way to "escape" the quote char in a quote. example:
        --   value1,"blub""blip""boing",value3  will result in blub"blip"boing  for the middle
      until (c ~= '"')
      table.insert(res,txt)
      assert(c == sep or c == "")
      pos = pos + 1
    else
      -- no quotes used, just look for the first separator
      local startp,endp = string.find(line,sep,pos)
      if (startp) then
        table.insert(res,string.sub(line,pos,startp-1))
        pos = endp + 1
      else
        -- no separator found -> use rest of string and terminate
        table.insert(res,string.sub(line,pos))
        break
      end
    end
  end
  return res
end


local function copyFile(fromFile, toFile, callback)
  callback = fireOnce(callback)
  local writeStream = fs.createWriteStream(toFile)
  local readStream = fs.createReadStream(fromFile)
  readStream:on('error', callback)
  readStream:on('end', callback)
  writeStream:on('error', callback)
  writeStream:on('end', callback)
  readStream:pipe(writeStream)
end

-- merge tables
local function merge(...)
  local args = {...}
  local first = args[1] or {}
  for i,t in pairs(args) do
    if i ~= 1 and t then
      for k, v in pairs(t) do
        first[k] = v
      end
    end
  end

  return first
end

-- Return true if an item is in a table, false otherwise.
-- f - function which is called on every item and should return true if the item
-- matches, false otherwise
-- t - table
local function tableContains(f, t)
  for _, v in ipairs(t) do
    if f(v) then
      return true
    end
  end

  return false
end

--[[
Split an address.

address - Address in ip:port format.
return [ip, port]
]]--
local function splitAddress(address)
  -- TODO: Split on last colon (ipv6)
  local start, result
  start, _ = address:find(':')

  if not start then
    return null
  end

  result = {}
  result[1] = address:sub(0, start - 1)
  result[2] = tonumber(address:sub(start + 1))
  return result
end

-- See Also: http://lua-users.org/wiki/SplitJoin
local function split(str, pattern)
  pattern = pattern or "[^%s]+"
  if pattern:len() == 0 then pattern = "[^%s]+" end
  local parts = {__index = table.insert}
  setmetatable(parts, parts)
  str:gsub(pattern, parts)
  setmetatable(parts, nil)
  parts.__index = nil
  return parts
end

local function tablePrint(tt, indent, done)
  done = done or {}
  indent = indent or 0
  if type(tt) == "table" then
    local sb = {}
    for key, value in pairs (tt) do
      table.insert(sb, string.rep (" ", indent)) -- indent it
      if type (value) == "table" and not done [value] then
        done [value] = true
        table.insert(sb, key .. " = {\n");
        table.insert(sb, tablePrint (value, indent + 2, done))
        table.insert(sb, string.rep (" ", indent)) -- indent it
        table.insert(sb, "}\n");
      elseif "number" == type(key) then
        table.insert(sb, string.format("\"%s\"\n", tostring(value)))
      else
        table.insert(sb, string.format(
        "%s = \"%s\"\n", tostring (key), tostring(value)))
      end
    end
    return table.concat(sb)
  else
    return tt .. "\n"
  end
end

local function toString(tbl)
  if  "nil"       == type( tbl ) then
    return tostring(nil)
  elseif  "table" == type( tbl ) then
    return tablePrint(tbl)
  elseif  "string" == type( tbl ) then
    return tbl
  else
    return tostring(tbl)
  end
end

-- Return start index of last occurance of a pattern in a string
function lastIndexOf(str, pat)
  local startIndex, endIndex
  local lastIndex = -1
  local found = false

  while 1 do
    startIndex, endIndex = string.find(str, pat, lastIndex + 1)
    if not startIndex then
      break
    else
      lastIndex = startIndex
    end
  end

  if lastIndex == -1 then
    return nil
  end

  return lastIndex
end

function fireOnce(callback)
  local called = false

  return function(...)
    if not called then
      called = true
      callback(unpack({...}))
    end
  end
end

function randstr(length)
  local chars, r, x

  chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  r = {}

  for x=1, length, 1 do
    local ch = string.char(string.byte(chars, math.random(1, #chars)))
    table.insert(r, ch)
  end

  return table.concat(r, '')
end

local exports = {}
exports.setDelta = setDelta
exports.getDelta = getDelta
exports.gmtNow = gmtNow
exports.gmtRaw = gmtRaw
exports.timesync = timesync
exports.crash = virgo.force_crash
exports.trim = trim
exports.tableGetBoolean = tableGetBoolean
exports.parseCSVLine = parseCSVLine
exports.copyFile = copyFile
exports.merge = merge
exports.tableContains = tableContains
exports.splitAddress = splitAddress
exports.split = split
exports.tablePrint = tablePrint
exports.toString = toString
exports.lastIndexOf = lastIndexOf
exports.fireOnce = fireOnce
exports.randstr = randstr
return exports
