#include "AddressSet.h"
#include "log.h"

#include <string>
#include <fstream>
#include <algorithm>

GameBuild gGameBuild = GameBuild::Unknown;
AddressSet gAddr{};

static const AddressSet kEnglish = {
    0x145F134E0ull, // IsArabLanguage
    0x1408D05F0ull, // GetFtexPathId
    0x146084A80ull, // GetGameLanguageState
    0x14094E950ull, // SetGameLanguageState
    0x14052F9C0ull, // GameConfigGetInstance
    0x145CC6360ull, // FixKorCh_Fun145cc6360
    0x14A4140D0ull, // SetSelectLangList
    0x141606250ull, // UpdateLangList
    0x14A412670ull, // DecideLangList
    0x141606490ull, // UpdateLangPopup
    0x14090F130ull, // ChangeLanguage
    0x1404E1E60ull, // ApplyFormVariation
    0x1400163F0ull, // FoxStringCtor
    0x140004200ull, // StdFree
    0x140085780ull, // PathCInitWithString
    0x140085650ull, // PathAssign
    0x140085610ull, // PathDtor
    0x140928D10ull, // LoadPageBlock
    0x14095CA10ull, // UnkLoadTppPartsLangFpk
    0x145F86420ull, // UnkLoadUIDefaultDataFunc
    0x140939A20ull, // GetUiUtility
    0x146089BD0ull, // GetTipsLangBlockPath
    0x145DDE150ull, // GetPauseHelpLangBlockPath
    0x1408DFFB0ull, // ShowTextureLogo
    0x140865D00ull, // CommonDataManager_GetInstance
    0x140867330ull, // CommonDataManager_SetDispLogo
    0x14D750C70ull, // UiLangInit
    0x1400CEF90ull, // FileRegisterLoadFunc
    0x141DF67B0ull, // LangLoadFuncHandler
    0x1408D78A0ull, // SetLuaFunctions
    0x14006B6D0ull, // FoxLuaRegisterLibrary
    0x141A123C0ull, // lua_tolstring
    0x141A12390ull, // lua_tointeger
    0x141A11BC0ull, // lua_pushnumber
    0x1409137A0ull, // GetStringId
    0x1400F1D50ull, // LuaCheckGlueString
    0x1400F21D0ull, // LuaToGlueString
    0x141A116B0ull, // lua_isstring
    0x141A11680ull, // lua_isnumber
    0x141A12460ull  // lua_tonumber

};

static const AddressSet kJapanese = {
    0x0ull, // IsArabLanguage
    0x0ull, // GetFtexPathId
    0x0ull, // GetGameLanguageState
    0x0ull, // SetGameLanguageState
    0x0ull, // GameConfigGetInstance
    0x0ull, // FixKorCh_Fun145cc6360
    0x0ull, // SetSelectLangList
    0x0ull, // UpdateLangList
    0x0ull, // DecideLangList
    0x0ull, // UpdateLangPopup
    0x0ull, // ChangeLanguage
    0x0ull, // ApplyFormVariation
    0x0ull, // FoxStringCtor
    0x0ull, // StdFree
    0x0ull, // PathCInitWithString
    0x0ull, // PathAssign
    0x0ull, // PathDtor
    0x0ull, // LoadPageBlock
    0x0ull, // UnkLoadTppPartsLangFpk
    0x0ull, // UnkLoadUIDefaultDataFunc
    0x0ull, // GetUiUtility
    0x0ull, // GetTipsLangBlockPath
    0x0ull, // GetPauseHelpLangBlockPath
    0x0ull, // ShowTextureLogo
    0x0ull, // CommonDataManager_GetInstance
    0x0ull, // CommonDataManager_SetDispLogo
    0x0ull, // UiLangInit
    0x0ull, // FileRegisterLoadFunc
    0x0ull, // LangLoadFuncHandler
    0x0ull, // SetLuaFunctions
    0x0ull, // FoxLuaRegisterLibrary
    0x0ull, // lua_tolstring
    0x0ull, // lua_tointeger
    0x0ull, // lua_pushnumber
    0x0ull, // GetStringId
    0x0ull, // LuaCheckGlueString
    0x0ull, // LuaToGlueString
    0x0ull, // lua_isstring
    0x0ull, // lua_isnumber
    0x0ull  // lua_tonumber
};

static std::wstring GetModuleDirectory(HMODULE hModule)
{
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(hModule, path, MAX_PATH))
        return L"";

    std::wstring fullPath(path);
    const size_t slash = fullPath.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return L"";

    return fullPath.substr(0, slash);
}

static std::string ReadWholeFileUtf8OrAnsi(const std::wstring& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};

    std::string content(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    return content;
}

static std::string ToLowerAscii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static GameBuild DetectGameBuildFromVersionInfo(HMODULE hGame)
{
    const std::wstring dir = GetModuleDirectory(hGame ? hGame : GetModuleHandleW(nullptr));
    if (dir.empty())
        return GameBuild::Unknown;

    const std::wstring versionInfoPath = dir + L"\\version_info.txt";
    std::string text = ReadWholeFileUtf8OrAnsi(versionInfoPath);
    if (text.empty())
    {
        Log("[AddressSet] Failed to read version_info.txt\n");
        return GameBuild::Unknown;
    }

    text = ToLowerAscii(text);

    Log("[AddressSet] version_info.txt = %s\n", text.c_str());

    if (text.find("mst_en") != std::string::npos)
        return GameBuild::English;

    else if (text.find("mst_jp") != std::string::npos)
        return GameBuild::Japanese;
    else
        return GameBuild::English;

    return GameBuild::Unknown;
}

const char* GetGameBuildName(GameBuild build)
{
    switch (build)
    {
    case GameBuild::English:  return "English";
    case GameBuild::Japanese: return "Japanese";
    default:                  return "Unknown";
    }
}

bool ResolveAddressSet(HMODULE hGame)
{
    if (!hGame)
        return false;

    gGameBuild = DetectGameBuildFromVersionInfo(hGame);

    switch (gGameBuild)
    {
    case GameBuild::English:
        gAddr = kEnglish;
        Log("[AddressSet] Selected English address set.\n");
        return true;

    case GameBuild::Japanese:
        gAddr = kJapanese;
        Log("[AddressSet] Selected Japanese address set.\n");
        return true;

    default:
        gAddr = {};
        Log("[AddressSet] Failed to detect supported game build.\n");
        return false;
    }
}