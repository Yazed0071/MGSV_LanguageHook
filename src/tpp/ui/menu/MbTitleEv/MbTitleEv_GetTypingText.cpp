#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using tpp_ui_menu_MbTitleEv_GetTypingText_t = uint8_t(__fastcall*)(void* thisPtr, char* outText, char* fullText);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_menu_MbTitleEv_GetTypingText_t gOrig_tpp_ui_menu_MbTitleEv_GetTypingText = nullptr;
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

/* Returns true if the byte is a UTF-8 lead byte. c = byte to test. */
static bool Utf8IsLeadByte(unsigned char c)
{
    return (c & 0xC0) != 0x80;
}

/* Collects UTF-8 character start offsets. s = UTF-8 string. */
static std::vector<size_t> Utf8CharOffsets(const char* s)
{
    std::vector<size_t> offsets;
    if (!s)
        return offsets;

    const unsigned char* p = reinterpret_cast<const unsigned char*>(s);
    size_t i = 0;

    while (p[i] != 0)
    {
        if (Utf8IsLeadByte(p[i]))
            offsets.push_back(i);
        ++i;
    }

    offsets.push_back(i);
    return offsets;
}

/* Builds the last N UTF-8 characters from the logical string. s = full text, charCountFromEnd = visible chars from the end. */
static std::string Utf8LogicalSuffix(const char* s, size_t charCountFromEnd)
{
    if (!s || !*s)
        return std::string();

    if (charCountFromEnd == 0)
        return std::string();

    const std::vector<size_t> offsets = Utf8CharOffsets(s);
    if (offsets.size() < 2)
        return std::string();

    const size_t totalChars = offsets.size() - 1;
    if (charCountFromEnd >= totalChars)
        return std::string(s);

    const size_t startChar = totalChars - charCountFromEnd;
    const size_t startByte = offsets[startChar];
    const size_t endByte = offsets[totalChars];

    return std::string(s + startByte, endByte - startByte);
}

/* Reads a byte safely. addr = source address, out = destination. */
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

/* Reads a 16-bit value safely. addr = source address, out = destination. */
static bool SafeReadU16(const void* addr, uint16_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint16_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

/* Writes a null-terminated string safely. dst = target buffer, dstSize = buffer size, src = text. */
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

/* Rebuilds the visible Arabic typing text from the end of fullText. thisPtr = MbTitleEv*, outText = output buffer, fullText = full source string, originalReturn = stock return value. */
static void FixArabicMbTitleTyping(void* thisPtr, char* outText, char* fullText, uint8_t originalReturn)
{
    if (!thisPtr || !outText || !fullText)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    uint8_t isTypingActive = 0;
    uint16_t revealCount = 0;

    if (!SafeReadU8(base + 0x12D4, isTypingActive))
        return;

    if (!SafeReadU16(base + 0x12D0, revealCount))
        return;

    if (!originalReturn && !isTypingActive)
        return;

    std::string visible = Utf8LogicalSuffix(fullText, revealCount);

    if (visible.empty() && revealCount != 0)
        visible = std::string(fullText);

    if (isTypingActive)
        visible += "_";

    SafeWriteCString(outText, 0x100, visible.c_str());
}

/* Hook for tpp::ui::menu::MbTitleEv::GetTypingText(this, outText, fullText). */
static uint8_t __fastcall hk_tpp_ui_menu_MbTitleEv_GetTypingText(void* thisPtr, char* outText, char* fullText)
{
    uint8_t ret = 0;

    if (gOrig_tpp_ui_menu_MbTitleEv_GetTypingText)
        ret = gOrig_tpp_ui_menu_MbTitleEv_GetTypingText(thisPtr, outText, fullText);

    if (!IsArabicSafe())
        return ret;

    FixArabicMbTitleTyping(thisPtr, outText, fullText, ret);
    return ret;
}

/* Installs the Arabic typing fix hook. hGame = game module handle. */
bool InstallMbTitleEvGetTypingTextArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.IsArabLanguage || !gAddr.GetTypingText)
    {
        Log("[tpp::ui::menu::MbTitleEv::GetTypingText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.GetTypingText);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hk_tpp_ui_menu_MbTitleEv_GetTypingText,
        reinterpret_cast<LPVOID*>(&gOrig_tpp_ui_menu_MbTitleEv_GetTypingText)) != MH_OK)
    {
        Log("[tpp::ui::menu::MbTitleEv::GetTypingText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[tpp::ui::menu::MbTitleEv::GetTypingText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[tpp::ui::menu::MbTitleEv::GetTypingText] Arabic typing fix hook enabled.\n");
    return true;
}

/* Removes the Arabic typing fix hook. */
void RemoveMbTitleEvGetTypingTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrig_tpp_ui_menu_MbTitleEv_GetTypingText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[tpp::ui::menu::MbTitleEv::GetTypingText] Arabic typing fix hook removed.\n");
}