#pragma once
#include <Windows.h>
#include <cstdint>

enum class GameBuild
{
    Unknown,
    English,
    Japanese
};

struct AddressSet
{
    uintptr_t IsArabLanguage = 0;
    uintptr_t GetFtexPathId = 0;
    uintptr_t GetGameLanguageState = 0;
    uintptr_t SetGameLanguageState = 0;
    uintptr_t GameConfigGetInstance = 0;
    uintptr_t FixKorCh_Fun145cc6360 = 0;
    uintptr_t SetSelectLangList = 0;
    uintptr_t UpdateLangList = 0;
    uintptr_t DecideLangList = 0;
    uintptr_t UpdateLangPopup = 0;
    uintptr_t ChangeLanguage = 0;
    uintptr_t ApplyFormVariation = 0;
    uintptr_t FoxStringCtor = 0;
    uintptr_t StdFree = 0;
    uintptr_t PathCInitWithString = 0;
    uintptr_t PathAssign = 0;
    uintptr_t PathDtor = 0;
    uintptr_t LoadPageBlock = 0;
    uintptr_t UnkLoadTppPartsLangFpk = 0;
    uintptr_t UnkLoadUIDefaultDataFunc = 0;
    uintptr_t GetUiUtility = 0;
    uintptr_t GetTipsLangBlockPath = 0;
    uintptr_t GetPauseHelpLangBlockPath = 0;
    uintptr_t ShowTextureLogo = 0;
    uintptr_t CommonDataManager_GetInstance = 0;
    uintptr_t CommonDataManager_SetDispLogo = 0;
    uintptr_t UiLangInit = 0;
    uintptr_t FileRegisterLoadFunc = 0;
    uintptr_t LangLoadFuncHandler = 0;
    uintptr_t SetLuaFunctions = 0;
    uintptr_t FoxLuaRegisterLibrary = 0;
    uintptr_t lua_tolstring = 0;
    uintptr_t lua_tointeger = 0;
    uintptr_t lua_pushnumber = 0;
    uintptr_t GetStringId = 0;
    uintptr_t LuaCheckGlueString = 0;
    uintptr_t LuaToGlueString = 0;
    uintptr_t lua_isstring = 0;
    uintptr_t lua_isnumber = 0;
    uintptr_t lua_tonumber = 0;
};

extern GameBuild gGameBuild;
extern AddressSet gAddr;

bool ResolveAddressSet(HMODULE hGame);
const char* GetGameBuildName(GameBuild build);