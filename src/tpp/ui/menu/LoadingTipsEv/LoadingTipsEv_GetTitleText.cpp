#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <cstdio>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using LoadingTipsEv_GetTitleText_t =
        uint64_t(__fastcall*)(uint64_t thisPtr, char mode, uint64_t param3, uint8_t param4);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static LoadingTipsEv_GetTitleText_t gOrigGetTitleText = nullptr;
    static void* gTarget = nullptr;
}

/* Checks Arabic state safely. */
static bool IsArabicSafe()
{
    if (!gIsArabLanguage)
        return false;

    __try
    {
        return gIsArabLanguage();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Safely reads a bounded c-string. */
static bool SafeReadCString(const char* src, size_t maxLen, std::string& out)
{
    __try
    {
        if (!src || maxLen == 0)
        {
            out.clear();
            return false;
        }

        size_t len = 0;
        while (len < maxLen && src[len] != '\0')
            ++len;

        out.assign(src, len);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out.clear();
        return false;
    }
}

/* Safely writes a bounded c-string. */
static bool SafeWriteCString(char* dst, size_t dstSize, const char* src)
{
    __try
    {
        if (!dst || dstSize == 0)
            return false;

        if (!src)
        {
            dst[0] = '\0';
            return true;
        }

        _snprintf_s(dst, dstSize, _TRUNCATE, "%s", src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Trims one trailing space if present before the "(x/y)" suffix. */
static std::string TrimRightOneSpace(const std::string& s)
{
    if (!s.empty() && s.back() == ' ')
        return s.substr(0, s.size() - 1);

    return s;
}

/* Rewrites "Movement Basics (1/5)" into "(5/1) Movement Basics". */
static std::string RewriteLoadingTipsTitleArabic(const std::string& src)
{
    if (src.empty())
        return src;

    const size_t openPos = src.rfind('(');
    if (openPos == std::string::npos)
        return src;

    int currentPage = 0;
    int totalPages = 0;

    if (sscanf_s(src.c_str() + openPos, "(%d/%d)", &currentPage, &totalPages) != 2)
        return src;

    std::string title = src.substr(0, openPos);
    title = TrimRightOneSpace(title);

    if (title.empty())
        return src;

    char rebuilt[128] = {};
    _snprintf_s(rebuilt, sizeof(rebuilt), _TRUNCATE, "(%d/%d) %s", totalPages, currentPage, title.c_str());
    return std::string(rebuilt);
}

/* Applies the Arabic title rewrite to the returned title buffer. */
static void ApplyArabicLoadingTipsTitleFix(uint64_t titleBuffer)
{
    if (!titleBuffer)
        return;

    char* titleBuf = reinterpret_cast<char*>(titleBuffer);

    std::string before;
    if (!SafeReadCString(titleBuf, 100, before))
        return;

    const std::string after = RewriteLoadingTipsTitleArabic(before);
    if (after == before)
        return;

    if (!SafeWriteCString(titleBuf, 100, after.c_str()))
        return;

    Log("[LoadingTipsEv::GetTitleText] before: %s\n", before.c_str());
    Log("[LoadingTipsEv::GetTitleText] after : %s\n", after.c_str());
}

/* Hook for LoadingTipsEv::GetTitleText(this, mode, param3, param4). */
static uint64_t __fastcall hkLoadingTipsEv_GetTitleText(
    uint64_t thisPtr,
    char mode,
    uint64_t param3,
    uint8_t param4)
{
    if (!gOrigGetTitleText)
        return 0;

    const uint64_t result = gOrigGetTitleText(thisPtr, mode, param3, param4);

    if (!result)
        return result;

    if (!IsArabicSafe())
        return result;

    ApplyArabicLoadingTipsTitleFix(result);
    return result;
}

/* Installs the LoadingTipsEv::GetTitleText Arabic hook. */
bool InstallLoadingTipsEvGetTitleTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.LoadingTipsEv_GetTitleText)
    {
        Log("[LoadingTipsEv::GetTitleText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.LoadingTipsEv_GetTitleText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkLoadingTipsEv_GetTitleText,
        reinterpret_cast<LPVOID*>(&gOrigGetTitleText)) != MH_OK)
    {
        Log("[LoadingTipsEv::GetTitleText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[LoadingTipsEv::GetTitleText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[LoadingTipsEv::GetTitleText] Arabic hook enabled.\n");
    return true;
}

/* Removes the LoadingTipsEv::GetTitleText Arabic hook. */
void RemoveLoadingTipsEvGetTitleTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigGetTitleText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[LoadingTipsEv::GetTitleText] Arabic hook removed.\n");
}