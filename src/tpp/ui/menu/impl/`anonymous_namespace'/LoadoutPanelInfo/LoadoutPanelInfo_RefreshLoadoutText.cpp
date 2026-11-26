#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <cctype>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using LoadoutPanelInfo_RefreshLoadoutText_t = void(__fastcall*)(void* thisPtr);

    using LoadoutSelectorRecord_Refresh_t = void(__fastcall*)(void* thisPtr);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static LoadoutPanelInfo_RefreshLoadoutText_t gOrigRefreshLoadoutText = nullptr;
    static LoadoutSelectorRecord_Refresh_t gOrigSelectorRefresh = nullptr;
    static LoadoutPanelInfo_RefreshLoadoutText_t gOrigMissionPrepRefresh = nullptr;
    static void* gTarget = nullptr;
    static void* gSelectorTarget = nullptr;
    static void* gMissionPrepTarget = nullptr;
    static int gLoadoutDiagBudget = 40;

    static constexpr uintptr_t kImageBase = 0x140000000ull;

    static constexpr size_t OFF_ROW_INDEX = 0x08;
    static constexpr size_t OFF_NAME_TEXT_ARRAY = 0x68;
    static constexpr size_t kMaxRowIndex = 64;
    static constexpr size_t kMaxRowTextBytes = 256;
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

/* Reads a bounded c-string safely. */
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

/* Writes a bounded c-string safely. */
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

/* Trims ASCII whitespace from both ends. */
static std::string TrimAscii(const std::string& s)
{
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])) != 0)
        ++start;

    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0)
        --end;

    return s.substr(start, end - start);
}

/* Returns true if the string is ASCII digits only. */
static bool IsAsciiDigitsOnly(const std::string& s)
{
    if (s.empty())
        return false;

    for (char c : s)
    {
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    }

    return true;
}

static std::string RewriteLeadingNumberToBack(const std::string& src)
{
    if (src.empty())
        return src;

    size_t start = 0;
    while (start < src.size() && std::isspace(static_cast<unsigned char>(src[start])) != 0)
        ++start;

    size_t numberEnd = start;
    while (numberEnd < src.size() && std::isdigit(static_cast<unsigned char>(src[numberEnd])) != 0)
        ++numberEnd;

    if (numberEnd == start)
        return src;

    if (numberEnd >= src.size())
        return src;

    if (std::isspace(static_cast<unsigned char>(src[numberEnd])) == 0)
        return src;

    const std::string number = src.substr(start, numberEnd - start);
    const std::string rest = TrimAscii(src.substr(numberEnd));

    if (rest.empty() || !IsAsciiDigitsOnly(number))
        return src;

    return rest + " " + number;
}

static std::string RewriteTrailingNumberToFront(const std::string& src)
{
    size_t end = src.size();
    while (end > 0 && std::isspace(static_cast<unsigned char>(src[end - 1])) != 0)
        --end;

    size_t numberStart = end;
    while (numberStart > 0 && std::isdigit(static_cast<unsigned char>(src[numberStart - 1])) != 0)
        --numberStart;

    if (numberStart == end || numberStart == 0 || std::isspace(static_cast<unsigned char>(src[numberStart - 1])) == 0)
        return src;

    const std::string rest = TrimAscii(src.substr(0, numberStart));
    if (rest.empty())
        return src;

    return src.substr(numberStart, end - numberStart) + " " + rest;
}

/* Rewrites one loadout text buffer if it matches the "%s %d" result shape. */
static void ApplyArabicLoadoutLineFix(char* buffer, size_t bufferSize, int lineIndex)
{
    if (!buffer || bufferSize == 0)
        return;

    std::string before;
    if (!SafeReadCString(buffer, bufferSize, before))
        return;

    const std::string after = RewriteTrailingNumberToFront(before);

    if (gLoadoutDiagBudget > 0 && RL_DiagnosticsEnabled())
    {
        --gLoadoutDiagBudget;
        LogDetail("[LoadoutDiag] line %d raw=[%s] rewritten=[%s] changed=%d\n",
            lineIndex, before.c_str(), after.c_str(), (after != before) ? 1 : 0);
    }

    if (after == before)
        return;

    if (!SafeWriteCString(buffer, bufferSize, after.c_str()))
        return;

    LogDetail("[LoadoutPanelInfo::RefreshLoadoutText] line %d before: %s\n", lineIndex, before.c_str());
    LogDetail("[LoadoutPanelInfo::RefreshLoadoutText] line %d after : %s\n", lineIndex, after.c_str());
}

/* Applies the Arabic reorder to the three numbered loadout lines. */
static void ApplyArabicRefreshLoadoutTextFix(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    ApplyArabicLoadoutLineFix(reinterpret_cast<char*>(base + 0x58), 0x77, 1);
    ApplyArabicLoadoutLineFix(reinterpret_cast<char*>(base + 0xCF), 0x77, 2);
    ApplyArabicLoadoutLineFix(reinterpret_cast<char*>(base + 0x146), 0x77, 3);
}

static bool SafeReadPtrLoadout(const void* addr, void*& out)
{
    __try
    {
        out = *reinterpret_cast<void* const*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = nullptr;
        return false;
    }
}

static bool SafeReadU32Loadout(const void* addr, uint32_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint32_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

static void SwapSelectorRowNumber(void* thisPtr)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    uint32_t index = 0;
    if (!SafeReadU32Loadout(base + OFF_ROW_INDEX, index))
        return;
    if (index >= kMaxRowIndex)
        return;

    void* textArray = nullptr;
    if (!SafeReadPtrLoadout(base + OFF_NAME_TEXT_ARRAY, textArray) || !textArray)
        return;

    void* textPtr = nullptr;
    if (!SafeReadPtrLoadout(reinterpret_cast<uint8_t*>(textArray) + index * sizeof(void*), textPtr))
        return;
    if (!textPtr)
        return;

    char* text = reinterpret_cast<char*>(textPtr);

    std::string before;
    if (!SafeReadCString(text, kMaxRowTextBytes, before) || before.empty())
        return;

    const std::string after = RewriteLeadingNumberToBack(before);
    if (after == before)
        return;

    if (after.size() != before.size())
        return;

    SafeWriteCString(text, before.size() + 1, after.c_str());
}

static void __fastcall hkMissionPreparation_RefreshLoadoutText(void* thisPtr)
{
    if (gOrigMissionPrepRefresh)
        gOrigMissionPrepRefresh(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyArabicRefreshLoadoutTextFix(thisPtr);
}

static void __fastcall hkLoadoutSelectorRecord_Refresh(void* thisPtr)
{
    if (thisPtr && IsArabicSafe())
        SwapSelectorRowNumber(thisPtr);

    if (gOrigSelectorRefresh)
        gOrigSelectorRefresh(thisPtr);
}

/* Hook for LoadoutPanelInfo::RefreshLoadoutText(this). */
static void __fastcall hkLoadoutPanelInfo_RefreshLoadoutText(void* thisPtr)
{
    if (gOrigRefreshLoadoutText)
        gOrigRefreshLoadoutText(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyArabicRefreshLoadoutTextFix(thisPtr);
}

/* Installs the LoadoutPanelInfo Arabic hook. */
bool InstallLoadoutPanelInfoRefreshLoadoutTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.LoadoutPanelInfo_RefreshLoadoutText)
    {
        Log("[LoadoutPanelInfo::RefreshLoadoutText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gTarget = reinterpret_cast<void*>(gAddr.LoadoutPanelInfo_RefreshLoadoutText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkLoadoutPanelInfo_RefreshLoadoutText,
        reinterpret_cast<LPVOID*>(&gOrigRefreshLoadoutText)) != MH_OK)
    {
        Log("[LoadoutPanelInfo::RefreshLoadoutText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[LoadoutPanelInfo::RefreshLoadoutText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[LoadoutPanelInfo::RefreshLoadoutText] Arabic hook enabled.\n");

    if (gAddr.LoadoutSelectorRecord_Refresh)
    {
        gSelectorTarget = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(hGame) + (gAddr.LoadoutSelectorRecord_Refresh - kImageBase));

        if (MH_CreateHook(
            gSelectorTarget,
            &hkLoadoutSelectorRecord_Refresh,
            reinterpret_cast<LPVOID*>(&gOrigSelectorRefresh)) == MH_OK &&
            MH_EnableHook(gSelectorTarget) == MH_OK)
        {
            Log("[LoadoutSelectorRecord::Refresh] Arabic row-number hook enabled.\n");
        }
        else
        {
            Log("[LoadoutSelectorRecord::Refresh] Hook failed.\n");
            gSelectorTarget = nullptr;
        }
    }
    else
    {
        Log("[LoadoutSelectorRecord::Refresh] No address for this build; row numbers unchanged.\n");
    }

    if (gAddr.MissionPreparationCallbackImpl_RefreshLoadoutText)
    {
        gMissionPrepTarget = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(hGame) +
            (gAddr.MissionPreparationCallbackImpl_RefreshLoadoutText - kImageBase));

        if (MH_CreateHook(
            gMissionPrepTarget,
            &hkMissionPreparation_RefreshLoadoutText,
            reinterpret_cast<LPVOID*>(&gOrigMissionPrepRefresh)) == MH_OK &&
            MH_EnableHook(gMissionPrepTarget) == MH_OK)
        {
            Log("[MissionPreparationCallbackImpl::RefreshLoadoutText] Arabic hook enabled.\n");
        }
        else
        {
            Log("[MissionPreparationCallbackImpl::RefreshLoadoutText] Hook failed.\n");
            gMissionPrepTarget = nullptr;
        }
    }
    else
    {
        Log("[MissionPreparationCallbackImpl::RefreshLoadoutText] No address for this build.\n");
    }

    return true;
}

/* Removes the LoadoutPanelInfo Arabic hook. */
void RemoveLoadoutPanelInfoRefreshLoadoutTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    if (gSelectorTarget)
    {
        MH_DisableHook(gSelectorTarget);
        MH_RemoveHook(gSelectorTarget);
        gSelectorTarget = nullptr;
    }

    if (gMissionPrepTarget)
    {
        MH_DisableHook(gMissionPrepTarget);
        MH_RemoveHook(gMissionPrepTarget);
        gMissionPrepTarget = nullptr;
    }

    gOrigRefreshLoadoutText = nullptr;
    gOrigSelectorRefresh = nullptr;
    gOrigMissionPrepRefresh = nullptr;
    gIsArabLanguage = nullptr;

    Log("[LoadoutPanelInfo::RefreshLoadoutText] Arabic hook removed.\n");
}