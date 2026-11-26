#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <cstdio>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using GetLangText_t = const char* (__fastcall*)(uint64_t langId);
    using LoadingTipsEv_GetTitleText_t =
        uint64_t(__fastcall*)(uint64_t thisPtr, char mode, uint64_t param3, uint8_t param4);
    using GetTipInfo_t = void(__fastcall*)(void* source, uint8_t index, uint64_t* id0, uint64_t* titleId,
                                           uint64_t* id2, int* page, int* pageCount);

    constexpr uint64_t kEmptyLangId = 0xB8A0BF169F98ull;
    constexpr size_t kGameTitleBufferSize = 100;
    constexpr size_t kTipSourceOffset = 0x1D0;
    constexpr size_t kGetTipInfoSlot = 2;
    constexpr int kTitleMode = 4;

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static GetLangText_t gGetLangText = nullptr;
    static LoadingTipsEv_GetTitleText_t gOrigGetTitleText = nullptr;
    static void* gTarget = nullptr;
    static char gFullTitle[1024] = {};
}

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

static bool QueryTipTitle(uint64_t thisPtr, uint8_t index, const char*& title, int& page, int& pageCount)
{
    __try
    {
        void* source = *reinterpret_cast<void**>(thisPtr + kTipSourceOffset);
        if (!source || !gGetLangText)
            return false;

        void** vtable = *reinterpret_cast<void***>(source);
        if (!vtable || !vtable[kGetTipInfoSlot])
            return false;

        uint64_t id0 = kEmptyLangId;
        uint64_t titleId = kEmptyLangId;
        uint64_t id2 = kEmptyLangId;
        page = 0;
        pageCount = 0;
        reinterpret_cast<GetTipInfo_t>(vtable[kGetTipInfoSlot])(source, index, &id0, &titleId, &id2, &page, &pageCount);

        title = gGetLangText(titleId);
        return title != nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static std::string TrimRightOneSpace(const std::string& s)
{
    if (!s.empty() && s.back() == ' ')
        return s.substr(0, s.size() - 1);

    return s;
}

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

    char rebuilt[1024] = {};
    _snprintf_s(rebuilt, sizeof(rebuilt), _TRUNCATE, "(%d/%d) %s", totalPages, currentPage, title.c_str());
    return std::string(rebuilt);
}

static void ApplyArabicLoadingTipsTitleFix(uint64_t titleBuffer)
{
    if (!titleBuffer)
        return;

    char* titleBuf = reinterpret_cast<char*>(titleBuffer);

    std::string before;
    if (!SafeReadCString(titleBuf, kGameTitleBufferSize, before))
        return;

    const std::string after = RewriteLoadingTipsTitleArabic(before);
    if (after == before)
        return;

    SafeWriteCString(titleBuf, kGameTitleBufferSize, after.c_str());
}

static uint64_t BuildFullArabicTitle(uint64_t thisPtr, uint8_t index, uint64_t gameResult)
{
    const char* title = nullptr;
    int page = 0;
    int pageCount = 0;
    if (!QueryTipTitle(thisPtr, index, title, page, pageCount))
        return 0;

    std::string text;
    if (!SafeReadCString(title, sizeof(gFullTitle) - 32, text))
        return 0;

    if (pageCount > 1)
    {
        char paged[sizeof(gFullTitle)] = {};
        _snprintf_s(paged, sizeof(paged), _TRUNCATE, "(%d/%d) %s", pageCount, page, text.c_str());
        text = paged;
    }

    std::string current;
    SafeReadCString(reinterpret_cast<const char*>(gameResult), kGameTitleBufferSize, current);
    if (text == current)
        return gameResult;

    _snprintf_s(gFullTitle, sizeof(gFullTitle), _TRUNCATE, "%s", text.c_str());
    if (text.size() >= kGameTitleBufferSize)
        Log("[LoadingTipsEv::GetTitleText] full title served (%zu bytes)\n", text.size());
    return reinterpret_cast<uint64_t>(gFullTitle);
}

void PrepareArabicLoadingTipBody(void* loadingTipsEv);

static uint64_t __fastcall hkLoadingTipsEv_GetTitleText(
    uint64_t thisPtr,
    char mode,
    uint64_t param3,
    uint8_t param4)
{
    if (!gOrigGetTitleText)
        return 0;

    const uint64_t result = gOrigGetTitleText(thisPtr, mode, param3, param4);

    if (!IsArabicSafe())
        return result;

    PrepareArabicLoadingTipBody(reinterpret_cast<void*>(thisPtr));

    if (!result)
        return result;

    if (mode == kTitleMode)
    {
        const uint64_t full = BuildFullArabicTitle(thisPtr, param4, result);
        if (full)
            return full;
    }

    ApplyArabicLoadingTipsTitleFix(result);
    return result;
}

bool InstallLoadingTipsEvGetTitleTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.LoadingTipsEv_GetTitleText)
    {
        Log("[LoadingTipsEv::GetTitleText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gGetLangText = reinterpret_cast<GetLangText_t>(gAddr.GetLangText);
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
    gGetLangText = nullptr;

    Log("[LoadingTipsEv::GetTitleText] Arabic hook removed.\n");
}
