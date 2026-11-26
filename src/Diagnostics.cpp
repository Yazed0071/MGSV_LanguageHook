#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstring>

namespace
{
    constexpr char SETTINGS_FILE[] = "MGSV_ExtendedLanguage.ini";
    constexpr char SETTINGS_SECTION[] = "Debug";
    constexpr char SETTINGS_KEY[] = "Diagnostics";

    std::atomic<int> gDiagnostics{ -1 };

    int ReadSetting()
    {
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameA(nullptr, path, MAX_PATH))
            return 0;
        char* slash = strrchr(path, '\\');
        if (!slash)
            return 0;
        slash[1] = '\0';
        if (strcat_s(path, SETTINGS_FILE) != 0)
            return 0;
        return GetPrivateProfileIntA(SETTINGS_SECTION, SETTINGS_KEY, 0, path) != 0 ? 1 : 0;
    }
}

bool RL_DiagnosticsEnabled()
{
#ifdef _DEBUG
    int value = gDiagnostics.load(std::memory_order_relaxed);
    if (value < 0)
    {
        value = ReadSetting();
        gDiagnostics.store(value, std::memory_order_relaxed);
    }
    return value != 0;
#else
    return false;
#endif
}
