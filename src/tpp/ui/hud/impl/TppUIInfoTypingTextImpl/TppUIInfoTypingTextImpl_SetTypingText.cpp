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
    using TppUIInfoTypingTextImpl_SetTypingText_t = void(__fastcall*)(void* thisPtr);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static TppUIInfoTypingTextImpl_SetTypingText_t gOrigSetTypingText = nullptr;
    static void* gTarget = nullptr;
}

/* Checks Arabic state safely. Takes no parameters. */
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

/* Reads one byte safely. addr = source address, out = destination byte. */
static bool SafeReadU8(const void* addr, uint8_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint8_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

/* Reads a bounded c-string safely. src = source buffer, maxLen = max bytes, out = destination string. */
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

/* Writes a bounded c-string safely. dst = target buffer, dstSize = buffer size, src = source text. */
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

/* Trims ASCII whitespace from both ends. s = source string. */
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

/* Returns true if the string is ASCII digits only. s = source string. */
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

/* Rewrites "text 12" into "12 text". src = original row text. */
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

/* Applies the Arabic row rewrite to one built row buffer. rowText = row buffer, rowIndex = row index for logging. */
static void ApplyArabicTypingRowFix(char* rowText, int rowIndex)
{
    if (!rowText)
        return;

    std::string before;
    if (!SafeReadCString(rowText, 200, before))
        return;

    const std::string after = RewriteTrailingNumberToFront(before);
    if (after == before)
        return;

    if (!SafeWriteCString(rowText, 200, after.c_str()))
        return;

    Log("[TppUIInfoTypingTextImpl::SetTypingText] row %d before: %s\n", rowIndex, before.c_str());
    Log("[TppUIInfoTypingTextImpl::SetTypingText] row %d after : %s\n", rowIndex, after.c_str());
}

/* Applies the Arabic fix to all active rows built by SetTypingText. thisPtr = TppUIInfoTypingTextImpl*. */
static void ApplyArabicTypingRows(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    for (int i = 0; i < 5; ++i)
    {
        const size_t rowStride = 0x1E0;
        const size_t activeOffset = 0x70 + static_cast<size_t>(i) * rowStride;
        const size_t textOffset = 0xA0 + static_cast<size_t>(i) * rowStride;

        uint8_t active = 0;
        if (!SafeReadU8(base + activeOffset, active))
            continue;

        if (active == 0)
            continue;

        char* rowText = reinterpret_cast<char*>(base + textOffset);
        ApplyArabicTypingRowFix(rowText, i);
    }
}

/* Hook for TppUIInfoTypingTextImpl::SetTypingText(this). */
static void __fastcall hkTppUIInfoTypingTextImpl_SetTypingText(void* thisPtr)
{
    if (gOrigSetTypingText)
        gOrigSetTypingText(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyArabicTypingRows(thisPtr);
}

/* Installs the SetTypingText Arabic hook. hGame = game module handle. */
bool InstallTppUIInfoTypingTextImplSetTypingTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.TppUIInfoTypingTextImpl_SetTypingText)
    {
        Log("[TppUIInfoTypingTextImpl::SetTypingText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.TppUIInfoTypingTextImpl_SetTypingText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkTppUIInfoTypingTextImpl_SetTypingText,
        reinterpret_cast<LPVOID*>(&gOrigSetTypingText)) != MH_OK)
    {
        Log("[TppUIInfoTypingTextImpl::SetTypingText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[TppUIInfoTypingTextImpl::SetTypingText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[TppUIInfoTypingTextImpl::SetTypingText] Arabic hook enabled.\n");
    return true;
}

/* Removes the SetTypingText Arabic hook. */
void RemoveTppUIInfoTypingTextImplSetTypingTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigSetTypingText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[TppUIInfoTypingTextImpl::SetTypingText] Arabic hook removed.\n");
}