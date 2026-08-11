#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using UpdateText_t = uint64_t(__fastcall*)(void* thisPtr, void* line);
    using GlyphByteLen_t = uint32_t(__fastcall*)(void* langSvc, const char* text, int32_t glyphCount, int32_t flag);
    using SetText_t = void(__fastcall*)(void* renderer, void* node, void* region, const char* text, uint64_t flag);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static UpdateText_t gOrigUpdateText = nullptr;
    static void* gTarget = nullptr;

    static constexpr size_t OFF_OWNER = 0x40;
    static constexpr size_t OFF_RENDERER = 0x20;
    static constexpr size_t OFF_LANGSVC = 0x48;

    static constexpr size_t VT_GLYPH_BYTE_LEN = 0x250;
    static constexpr size_t VT_SETTEXT = 0x708;

    static constexpr size_t LINE_STATE = 0x00;
    static constexpr size_t LINE_REVEAL = 0x04;
    static constexpr size_t LINE_TOTAL = 0x08;
    static constexpr size_t LINE_REGION = 0x10;
    static constexpr size_t LINE_NODE_A = 0x20;
    static constexpr size_t LINE_NODE_B = 0x28;
    static constexpr size_t LINE_SOURCE = 0x30;
    static constexpr size_t LINE_VISIBLE = 0xF8;
    static constexpr size_t SOURCE_CAPACITY = 0xC8;
    static constexpr size_t VISIBLE_CAPACITY = 0xC8;

    static constexpr size_t OFF_ALIGN = 0xD8;
    static constexpr size_t OFF_ALIGN_DRIVER = 0xDA;
    static constexpr uint8_t ALIGN_RIGHT = 2;

    static constexpr uint8_t STATE_TYPING = 2;
    static constexpr int32_t GLYPH_FLAG = 1;
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

static bool ReadPtr(const void* addr, void*& out)
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

static bool ReadU8(const void* addr, uint8_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint8_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0xFF;
        return false;
    }
}

static bool WriteU8(void* addr, uint8_t value)
{
    __try
    {
        *reinterpret_cast<uint8_t*>(addr) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ReadS32(const void* addr, int32_t& out)
{
    __try
    {
        out = *reinterpret_cast<const int32_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

static bool CallGlyphByteLen(void* langSvc, const char* text, int32_t glyphCount, uint32_t& out)
{
    __try
    {
        void* vtable = *reinterpret_cast<void* const*>(langSvc);
        if (!vtable)
            return false;

        GlyphByteLen_t fn = *reinterpret_cast<GlyphByteLen_t const*>(
            reinterpret_cast<const uint8_t*>(vtable) + VT_GLYPH_BYTE_LEN);
        if (!fn)
            return false;

        out = fn(langSvc, text, glyphCount, GLYPH_FLAG);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

static bool CallSetText(void* renderer, void* node, void* region, const char* text)
{
    __try
    {
        void* vtable = *reinterpret_cast<void* const*>(renderer);
        if (!vtable)
            return false;

        SetText_t fn = *reinterpret_cast<SetText_t const*>(
            reinterpret_cast<const uint8_t*>(vtable) + VT_SETTEXT);
        if (!fn)
            return false;

        fn(renderer, node, region, text, 1);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool CopyTail(char* visible, const char* source, uint32_t suffixStart)
{
    __try
    {
        if (suffixStart >= SOURCE_CAPACITY)
            return false;

        const char* tail = source + suffixStart;

        size_t i = 0;
        while (i + 1 < VISIBLE_CAPACITY && tail[i] != '\0')
        {
            visible[i] = tail[i];
            ++i;
        }
        visible[i] = '\0';
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool GetOwnerSub(void* thisPtr, size_t subOffset, void*& out)
{
    out = nullptr;

    void* owner = nullptr;
    if (!ReadPtr(reinterpret_cast<uint8_t*>(thisPtr) + OFF_OWNER, owner) || !owner)
        return false;

    return ReadPtr(reinterpret_cast<uint8_t*>(owner) + subOffset, out) && out != nullptr;
}

static void RightAlignNode(void* node)
{
    if (!node)
        return;

    uint8_t d8 = 0xFF;
    uint8_t da = 0xFF;
    ReadU8(reinterpret_cast<uint8_t*>(node) + OFF_ALIGN, d8);
    ReadU8(reinterpret_cast<uint8_t*>(node) + OFF_ALIGN_DRIVER, da);

    if (d8 <= 3)
        WriteU8(reinterpret_cast<uint8_t*>(node) + OFF_ALIGN, ALIGN_RIGHT);
    if (da <= 3)
        WriteU8(reinterpret_cast<uint8_t*>(node) + OFF_ALIGN_DRIVER, ALIGN_RIGHT);
}

static void ApplyRtlTyping(void* thisPtr, void* line)
{
    uint8_t state = 0;
    if (!ReadU8(reinterpret_cast<uint8_t*>(line) + LINE_STATE, state) || state != STATE_TYPING)
        return;

    int32_t reveal = 0;
    if (!ReadS32(reinterpret_cast<uint8_t*>(line) + LINE_REVEAL, reveal) || reveal <= 0)
        return;

    int32_t total = 0;
    if (!ReadS32(reinterpret_cast<uint8_t*>(line) + LINE_TOTAL, total) || total <= 0)
        return;

    void* region = nullptr;
    if (!ReadPtr(reinterpret_cast<uint8_t*>(line) + LINE_REGION, region) || !region)
        return;

    void* nodeA = nullptr;
    void* nodeB = nullptr;
    ReadPtr(reinterpret_cast<uint8_t*>(line) + LINE_NODE_A, nodeA);
    ReadPtr(reinterpret_cast<uint8_t*>(line) + LINE_NODE_B, nodeB);

    if (reveal < total)
    {
        void* langSvc = nullptr;
        void* renderer = nullptr;
        if (GetOwnerSub(thisPtr, OFF_LANGSVC, langSvc) && GetOwnerSub(thisPtr, OFF_RENDERER, renderer))
        {
            char* source = reinterpret_cast<char*>(line) + LINE_SOURCE;
            char* visible = reinterpret_cast<char*>(line) + LINE_VISIBLE;

            uint32_t suffixStart = 0;
            if (CallGlyphByteLen(langSvc, source, total - reveal, suffixStart) &&
                CopyTail(visible, source, suffixStart))
            {
                if (nodeA)
                    CallSetText(renderer, nodeA, region, visible);
                if (nodeB)
                    CallSetText(renderer, nodeB, region, visible);
            }
        }
    }

    RightAlignNode(nodeA);
    RightAlignNode(nodeB);
}

static uint64_t __fastcall hkUpdateText(void* thisPtr, void* line)
{
    const uint64_t ret = gOrigUpdateText ? gOrigUpdateText(thisPtr, line) : 0;

    if (thisPtr && line && IsArabicSafe())
        ApplyRtlTyping(thisPtr, line);

    return ret;
}

bool InstallTppUIInfoTypingTextUpdateTextRtlHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.TppUIInfoTypingText_UpdateText)
    {
        Log("[TppUIInfoTypingText::UpdateText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.TppUIInfoTypingText_UpdateText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkUpdateText,
        reinterpret_cast<LPVOID*>(&gOrigUpdateText)) != MH_OK ||
        MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[TppUIInfoTypingText::UpdateText] Hook install failed.\n");
        gTarget = nullptr;
        return false;
    }

    Log("[TppUIInfoTypingText::UpdateText] Arabic RTL typing hook enabled.\n");
    return true;
}

void RemoveTppUIInfoTypingTextUpdateTextRtlHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigUpdateText = nullptr;
    gIsArabLanguage = nullptr;
}
