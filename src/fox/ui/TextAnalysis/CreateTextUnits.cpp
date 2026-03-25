#include <windows.h>
#include <cstdint>
#include <vector>
#include <algorithm>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

using IsArabLanguage_t = bool(__cdecl*)();
using CreateTextUnits_t = int(__fastcall*)(
    char* text,
    float* fontGroup,
    float* rubyFontGroup,
    unsigned int fontId,
    unsigned int flags,
    float displayWidth,
    void* textUnits,
    int maxUnits);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static CreateTextUnits_t oCreateTextUnits = nullptr;
static void* gTargetCreateTextUnits = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static thread_local bool gInCreateTextUnitsPostFix = false;

#pragma pack(push, 1)
/* Reads only the fields this hook needs from the final emitted TextUnit. Parameters: none. */
struct TextUnitLite
{
    char* text;
    uint32_t unk08;
    uint32_t flags;
    uint16_t charCount;
    uint16_t lineIndex;
    uint32_t unk14;
    uint64_t unk18;
};
#pragma pack(pop)

static_assert(sizeof(TextUnitLite) == 0x20, "TextUnitLite must be 0x20 bytes");

/* Converts an IDA absolute VA to a runtime VA. Parameters: hGame = module base, absVa = absolute address from IDA. */
static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

/* Safely checks whether Arabic mode is enabled. Parameters: none. */
static __forceinline bool IsArabicSafe()
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

/* Reads one UTF-8 codepoint and advances the pointer. Parameters: s = input cursor, cp = decoded codepoint. */
static bool NextUtf8Codepoint(const char*& s, uint32_t& cp)
{
    if (!s || !*s)
        return false;

    const unsigned char c0 = static_cast<unsigned char>(*s++);

    if (c0 < 0x80)
    {
        cp = c0;
        return true;
    }

    if ((c0 >> 5) == 0x6)
    {
        if (!*s)
        {
            cp = c0;
            return true;
        }

        const unsigned char c1 = static_cast<unsigned char>(*s++);
        cp = ((c0 & 0x1F) << 6) | (c1 & 0x3F);
        return true;
    }

    if ((c0 >> 4) == 0xE)
    {
        if (!s[0] || !s[1])
        {
            cp = c0;
            return true;
        }

        const unsigned char c1 = static_cast<unsigned char>(*s++);
        const unsigned char c2 = static_cast<unsigned char>(*s++);
        cp = ((c0 & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F);
        return true;
    }

    if ((c0 >> 3) == 0x1E)
    {
        if (!s[0] || !s[1] || !s[2])
        {
            cp = c0;
            return true;
        }

        const unsigned char c1 = static_cast<unsigned char>(*s++);
        const unsigned char c2 = static_cast<unsigned char>(*s++);
        const unsigned char c3 = static_cast<unsigned char>(*s++);
        cp = ((c0 & 0x07) << 18) | ((c1 & 0x3F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
        return true;
    }

    cp = c0;
    return true;
}

/* Detects Arabic-related codepoints in UTF-8 text. Parameters: text = UTF-8 string. */
static bool ContainsArabicUtf8(const char* text)
{
    if (!text)
        return false;

    const char* p = text;
    uint32_t cp = 0;

    while (*p)
    {
        const char* before = p;
        if (!NextUtf8Codepoint(p, cp))
            break;

        if ((cp >= 0x0600 && cp <= 0x06FF) ||
            (cp >= 0x0750 && cp <= 0x077F) ||
            (cp >= 0x08A0 && cp <= 0x08FF) ||
            (cp >= 0xFB50 && cp <= 0xFDFF) ||
            (cp >= 0xFE70 && cp <= 0xFEFF) ||
            (cp >= 0x1EE00 && cp <= 0x1EEFF))
        {
            return true;
        }

        if (p == before)
            ++p;
    }

    return false;
}

/* Skips tagged strings so UI markup is not touched. Parameters: text = source text. */
static bool HasMarkupTags(const char* text)
{
    if (!text)
        return false;

    for (const char* p = text; *p; ++p)
    {
        if (*p == '<')
            return true;
    }

    return false;
}

/* Skips strings with manual line breaks. Parameters: text = source text. */
static bool HasExplicitLineBreaks(const char* text)
{
    if (!text)
        return false;

    for (const char* p = text; *p; ++p)
    {
        if (*p == '\n' || *p == '\r')
            return true;
    }

    return false;
}

/* Reverses final emitted line groups and remaps lineIndex. Parameters: units = output array, count = emitted unit count. */
static void ReverseFinalArabicLineOrder(TextUnitLite* units, int count)
{
    if (!units || count <= 1)
        return;

    std::vector<uint16_t> uniqueLines;
    uniqueLines.reserve(static_cast<size_t>(count));

    for (int i = 0; i < count; ++i)
    {
        const uint16_t line = units[i].lineIndex;
        if (std::find(uniqueLines.begin(), uniqueLines.end(), line) == uniqueLines.end())
            uniqueLines.push_back(line);
    }

    if (uniqueLines.size() <= 1)
        return;

    std::sort(uniqueLines.begin(), uniqueLines.end());

    std::vector<TextUnitLite> reordered;
    reordered.reserve(static_cast<size_t>(count));

    uint16_t newLineIndex = 0;

    for (auto it = uniqueLines.rbegin(); it != uniqueLines.rend(); ++it, ++newLineIndex)
    {
        const uint16_t oldLine = *it;

        for (int i = 0; i < count; ++i)
        {
            if (units[i].lineIndex == oldLine)
            {
                TextUnitLite copy = units[i];
                copy.lineIndex = newLineIndex;
                reordered.push_back(copy);
            }
        }
    }

    if (static_cast<int>(reordered.size()) != count)
        return;

    for (int i = 0; i < count; ++i)
        units[i] = reordered[static_cast<size_t>(i)];
}

/* Post-fixes final Arabic line order after the original function emits TextUnits. Parameters match the original function. */
static int __fastcall hkCreateTextUnits(
    char* text,
    float* fontGroup,
    float* rubyFontGroup,
    unsigned int fontId,
    unsigned int flags,
    float displayWidth,
    void* textUnits,
    int maxUnits)
{
    if (!oCreateTextUnits)
        return 0;

    const int result = oCreateTextUnits(
        text,
        fontGroup,
        rubyFontGroup,
        fontId,
        flags,
        displayWidth,
        textUnits,
        maxUnits);

    if (gInCreateTextUnitsPostFix ||
        result <= 1 ||
        !IsArabicSafe() ||
        !text ||
        !textUnits ||
        maxUnits <= 0 ||
        !ContainsArabicUtf8(text) ||
        HasMarkupTags(text) ||
        HasExplicitLineBreaks(text))
    {
        return result;
    }

    gInCreateTextUnitsPostFix = true;

    int unitCount = result;
    if (unitCount > maxUnits)
        unitCount = maxUnits;

    if (unitCount > 1)
    {
        TextUnitLite* units = reinterpret_cast<TextUnitLite*>(textUnits);
        ReverseFinalArabicLineOrder(units, unitCount);
    }

    gInCreateTextUnitsPostFix = false;
    return result;
}

/* Installs the CreateTextUnits post-fix hook. Parameters: hGame = game module handle. */
bool InstallCreateTextUnitsArabicWrapHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTargetCreateTextUnits =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.CreateTextUnits));

    if (!gTargetCreateTextUnits)
    {
        Log("[TextAnalysis::CreateTextUnits] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetCreateTextUnits,
            reinterpret_cast<void*>(&hkCreateTextUnits),
            reinterpret_cast<void**>(&oCreateTextUnits));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[TextAnalysis::CreateTextUnits] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetCreateTextUnits);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[TextAnalysis::CreateTextUnits] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[TextAnalysis::CreateTextUnits] Arabic final-line-order hook enabled.\n");
    return true;
}

/* Removes the CreateTextUnits post-fix hook. Parameters: none. */
void RemoveCreateTextUnitsArabicWrapHook()
{
    if (gTargetCreateTextUnits)
    {
        MH_DisableHook(gTargetCreateTextUnits);
        MH_RemoveHook(gTargetCreateTextUnits);
        gTargetCreateTextUnits = nullptr;
    }

    oCreateTextUnits = nullptr;
    gIsArabLanguage = nullptr;
}