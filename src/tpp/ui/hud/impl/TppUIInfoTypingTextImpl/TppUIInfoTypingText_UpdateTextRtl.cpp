#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <atomic>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using UpdateText_t = uint64_t(__fastcall*)(void* thisPtr, void* line);
    using GlyphByteLen_t = uint32_t(__fastcall*)(void* langSvc, const char* text, int32_t glyphCount, int32_t flag);
    using SetText_t = void(__fastcall*)(void* renderer, void* node, void* region, const char* text, uint64_t flag);
    using SetTranslateX_t = void(__fastcall*)(void* renderer, void* node, float x);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static UpdateText_t gOrigUpdateText = nullptr;
    static void* gTarget = nullptr;

    static constexpr size_t OFF_OWNER = 0x40;
    static constexpr size_t OFF_RENDERER = 0x20;
    static constexpr size_t OFF_LANGSVC = 0x48;

    static constexpr size_t VT_GLYPH_BYTE_LEN = 0x250;
    static constexpr size_t VT_SETTEXT = 0x708;
    static constexpr size_t VT_SET_TRANSLATE_X = 0x350;
    static constexpr size_t OFF_INFO = 0x48;
    static constexpr size_t INFO_OFFSET_X = 0x80;
    static constexpr size_t UNIT_WIDTH = 0x14;

    static constexpr size_t LINE_STATE = 0x00;
    static constexpr size_t LINE_REVEAL = 0x04;
    static constexpr size_t LINE_TOTAL = 0x08;
    static constexpr size_t LINE_REGION = 0x10;
    static constexpr size_t LINE_PARENT = 0x18;
    static constexpr size_t LINE_NODE_A = 0x20;
    static constexpr size_t LINE_NODE_B = 0x28;
    static constexpr size_t LINE_SOURCE = 0x30;
    static constexpr size_t LINE_VISIBLE = 0xF8;
    static constexpr size_t SOURCE_CAPACITY = 0xC8;
    static constexpr size_t VISIBLE_CAPACITY = 0xC8;
    static constexpr size_t LINE_BASE_X = 0x1C4;

    static constexpr float ANCHOR_FROM_BASE = 35.0f;
    static constexpr float WIDTH_TO_TRANSLATE = 0.1f;

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

static bool CallSetTranslateX(void* renderer, void* node, float x)
{
    __try
    {
        void* vtable = *reinterpret_cast<void* const*>(renderer);
        if (!vtable)
            return false;

        SetTranslateX_t fn = *reinterpret_cast<SetTranslateX_t const*>(
            reinterpret_cast<const uint8_t*>(vtable) + VT_SET_TRANSLATE_X);
        if (!fn)
            return false;

        fn(renderer, node, x);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ReadF32(const void* addr, float& out)
{
    __try
    {
        out = *reinterpret_cast<const float*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0.0f;
        return false;
    }
}

static void PinRowRightEdge(void* thisPtr, void* line)
{
    auto* row = static_cast<uint8_t*>(line);
    uint8_t firstByte = 0;
    if (!ReadU8(row + LINE_SOURCE, firstByte) || firstByte == 0)
        return;

    void* region = nullptr;
    void* parent = nullptr;
    void* info = nullptr;
    void* renderer = nullptr;
    float width = 0.0f;
    float base = 0.0f;
    float offsetX = 0.0f;
    if (!ReadPtr(row + LINE_REGION, region) || !region || !ReadPtr(row + LINE_PARENT, parent) || !parent ||
        !ReadPtr(static_cast<uint8_t*>(thisPtr) + OFF_INFO, info) || !info ||
        !GetOwnerSub(thisPtr, OFF_RENDERER, renderer) ||
        !ReadF32(static_cast<uint8_t*>(region) + UNIT_WIDTH, width) || !(width > 0.0f) ||
        !ReadF32(row + LINE_BASE_X, base) || !ReadF32(static_cast<uint8_t*>(info) + INFO_OFFSET_X, offsetX))
        return;

    CallSetTranslateX(renderer, parent, base + ANCHOR_FROM_BASE + offsetX - width * WIDTH_TO_TRANSLATE);
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
}

static uint64_t __fastcall hkUpdateText(void* thisPtr, void* line)
{
    const uint64_t ret = gOrigUpdateText ? gOrigUpdateText(thisPtr, line) : 0;

    if (thisPtr && line && IsArabicSafe())
    {
        ApplyRtlTyping(thisPtr, line);
        PinRowRightEdge(thisPtr, line);
    }

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

    gIsArabLanguage = &RL_IsRightToLeft;
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
