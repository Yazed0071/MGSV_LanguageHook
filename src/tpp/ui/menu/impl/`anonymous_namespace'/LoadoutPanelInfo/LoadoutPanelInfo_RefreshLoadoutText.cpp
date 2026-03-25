#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <cctype>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using LoadoutPanelInfo_RefreshLoadoutText_t = void(__fastcall*)(void* thisPtr);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static LoadoutPanelInfo_RefreshLoadoutText_t gOrigRefreshLoadoutText = nullptr;
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

/* Rewrites "text 1" into "1 text". */
static std::string RewriteTrailingNumberToFront(const std::string& src)
{
    if (src.empty())
        return src;

    size_t end = src.size();
    while (end > 0 && std::isspace(static_cast<unsigned char>(src[end - 1])) != 0)
        --end;

    if (end == 0)
        return src;

    size_t numberStart = end;
    while (numberStart > 0 && std::isdigit(static_cast<unsigned char>(src[numberStart - 1])) != 0)
        --numberStart;

    if (numberStart == end)
        return src;

    if (numberStart == 0)
        return src;

    if (std::isspace(static_cast<unsigned char>(src[numberStart - 1])) == 0)
        return src;

    const std::string left = TrimAscii(src.substr(0, numberStart));
    const std::string right = src.substr(numberStart, end - numberStart);

    if (left.empty() || !IsAsciiDigitsOnly(right))
        return src;

    return right + " " + left;
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
    if (after == before)
        return;

    if (!SafeWriteCString(buffer, bufferSize, after.c_str()))
        return;

    Log("[LoadoutPanelInfo::RefreshLoadoutText] line %d before: %s\n", lineIndex, before.c_str());
    Log("[LoadoutPanelInfo::RefreshLoadoutText] line %d after : %s\n", lineIndex, after.c_str());
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

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
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

    gOrigRefreshLoadoutText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[LoadoutPanelInfo::RefreshLoadoutText] Arabic hook removed.\n");
}