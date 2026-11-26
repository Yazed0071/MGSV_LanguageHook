local this = {}

if rawget(_G, "V_Restored_Languages") then
    return _G.V_Restored_Languages
end

local ok, V_Restored_LanguagesOrErr = pcall(require, "V_Restored_Languages")
if not ok then
    error("V_Restored_Languages: V_Restored_Languages.dll is not running (" .. tostring(V_Restored_LanguagesOrErr) .. "). "
        .. "It goes in MGS_TPP\\plugins\\ and is started with the game by msacm32.dll in MGS_TPP\\. "
        .. "Steam Deck / Linux: set the game's Steam launch options to  WINEDLLOVERRIDES=\"msacm32=n,b\" %command%")
end

local V_Restored_Languages = V_Restored_LanguagesOrErr

_G.V_RL = V_Restored_Languages
_G.V_Restored_Languages_Addon = V_Restored_Languages
_G.V_Restored_Languages = this

this.V_Restored_Languages = V_Restored_Languages

return this