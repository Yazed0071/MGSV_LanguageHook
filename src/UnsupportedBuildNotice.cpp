#include "pch.h"
#include <Windows.h>
#include <string>
#include "log.h"

const wchar_t* RL_UnsupportedBuildText(int langId);

namespace
{
    constexpr int LANG_ID_ENGLISH = 0;
    constexpr int LANG_ID_ARABIC = 6;

    std::wstring ExeDirectory()
    {
        wchar_t path[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (length == 0 || length >= MAX_PATH)
            return {};
        std::wstring full(path, length);
        const size_t slash = full.find_last_of(L"\\/");
        return slash == std::wstring::npos ? std::wstring() : full.substr(0, slash + 1);
    }

    bool HostIsGame()
    {
        wchar_t path[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (length == 0 || length >= MAX_PATH)
            return false;
        const wchar_t* name = wcsrchr(path, L'\\');
        name = name ? name + 1 : path;
        return _wcsicmp(name, L"mgsvtpp.exe") == 0;
    }

    int LangFromWindows()
    {
        switch (PRIMARYLANGID(GetUserDefaultUILanguage()))
        {
        case LANG_FRENCH: return 1;
        case LANG_ITALIAN: return 2;
        case LANG_GERMAN: return 3;
        case LANG_SPANISH: return 4;
        case LANG_PORTUGUESE: return 5;
        case LANG_ARABIC: return 6;
        case LANG_RUSSIAN: return 7;
        case LANG_JAPANESE: return 8;
        case LANG_CHINESE: return 9;
        case LANG_KOREAN: return 10;
        default: return LANG_ID_ENGLISH;
        }
    }

    int ChooseLanguage()
    {
        const std::wstring ini = ExeDirectory() + L"MGSV_ExtendedLanguage.ini";
        const int saved = static_cast<int>(GetPrivateProfileIntW(L"Language", L"SelectedLangId", -1, ini.c_str()));
        if (saved >= 0 && saved <= 10)
            return saved;
        return LangFromWindows();
    }

    DWORD WINAPI ShowNotice(LPVOID)
    {
        const int lang = ChooseLanguage();
        std::wstring text = RL_UnsupportedBuildText(lang);
        if (lang != LANG_ID_ENGLISH)
        {
            text += L"\n\n";
            text += RL_UnsupportedBuildText(LANG_ID_ENGLISH);
        }
        UINT flags = MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND;
        if (lang == LANG_ID_ARABIC)
            flags |= MB_RTLREADING | MB_RIGHT;
        MessageBoxW(nullptr, text.c_str(), L"Restored Languages", flags);
        return 0;
    }
}

void RL_ShowUnsupportedBuildNotice()
{
    if (!HostIsGame())
        return;
    Log("[DLL] unsupported game version - the warning message is shown and the mod stays off.\n");
    HANDLE thread = CreateThread(nullptr, 0, &ShowNotice, nullptr, 0, nullptr);
    if (thread)
        CloseHandle(thread);
}
