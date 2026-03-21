local this = {}

if rawget(_G, "Lost_Languages") then
    return _G.Lost_Languages
end

local ok, ArabicOrErr = pcall(require, "Lost_Languages")
if not ok then
    error("Lost_Languages: failed to require Lost_Languages: " .. tostring(ArabicOrErr))
end

local Lost_Languages = ArabicOrErr

_G.ARA = Lost_Languages
_G.Lost_Languages_Addon = Lost_Languages
_G.Lost_Languages = this

this.Lost_Languages = Lost_Languages

return this