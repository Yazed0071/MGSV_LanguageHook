local this = {}

if rawget(_G, "V_Restored_Languages") then
    return _G.V_Restored_Languages
end

local ok, V_Restored_LanguagesOrErr = pcall(require, "V_Restored_Languages")
if not ok then
    error("V_Restored_Languages: failed to require V_Restored_Languages: " .. tostring(V_Restored_LanguagesOrErr))
end

local V_Restored_Languages = V_Restored_LanguagesOrErr

_G.V_RL = V_Restored_Languages
_G.V_Restored_Languages_Addon = V_Restored_Languages
_G.V_Restored_Languages = this

this.V_Restored_Languages = V_Restored_Languages

return this