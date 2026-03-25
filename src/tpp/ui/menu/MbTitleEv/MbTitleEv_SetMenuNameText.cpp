// MbTitleEv_SetMenuNameText_ArabicHook.cpp

#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cstdio>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using SetMenuNameText_t = void(__fastcall*)(void* thisPtr, uint64_t* ids);
    using GetLangText_t = const char* (__fastcall*)(uint64_t langId);
    using SetTextForModelNodeText_t =
        void(__fastcall*)(void* modelNodeText, void* textUnit, const char* text, uint8_t flag);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static SetMenuNameText_t gOrigSetMenuNameText = nullptr;
    static GetLangText_t gGetLangText = nullptr;
    static SetTextForModelNodeText_t gSetTextForModelNodeText = nullptr;
    static void* gTarget = nullptr;

    static constexpr uint8_t TEXT_ALIGN_LEFT = 0;
    static constexpr uint8_t TEXT_ALIGN_CENTER = 1;
    static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

    static constexpr uint64_t EMPTY_STRING_ID = 0x0000B8A0BF169F98ull;
}

/* Checks Arabic state safely. Params: none. */
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

/* Checks if a StrCode64 is the empty-string id. Params: value = id to test. */
static bool IsEmptyStrCode64(uint64_t value)
{
    return (value & 0xFFFFFFFFFFFFull) == (EMPTY_STRING_ID & 0xFFFFFFFFFFFFull);
}

/* Reads one byte safely. Params: addr = source, out = result. */
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

/* Reads one 16-bit value safely. Params: addr = source, out = result. */
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

/* Reads one pointer safely. Params: addr = source, out = result. */
static bool SafeReadPtr(const void* addr, void*& out)
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

/* Writes a bounded c-string safely. Params: dst = output buffer, dstSize = size, src = text. */
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

        std::snprintf(dst, dstSize, "%s", src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Writes one byte safely. Params: addr = destination, value = byte to write. */
static bool SafeWriteU8(void* addr, uint8_t value)
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

/* Returns true if byte is a UTF-8 lead byte. Params: c = byte. */
static bool Utf8IsLeadByte(unsigned char c)
{
    return (c & 0xC0) != 0x80;
}

/* Counts UTF-8 characters. Params: s = utf8 text. */
static size_t Utf8CharLen(const char* s)
{
    if (!s)
        return 0;

    size_t count = 0;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(s);

    while (*p)
    {
        if (Utf8IsLeadByte(*p))
            ++count;
        ++p;
    }

    return count;
}

/* Collects UTF-8 character offsets. Params: s = utf8 text. */
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

/* Returns the last N UTF-8 chars in logical order. Params: s = text, charCountFromEnd = reveal count. */
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

/* Collects localized breadcrumb parts from ids. Params: ids = StrCode64 array. */
static std::vector<std::string> CollectLocalizedParts(uint64_t* ids)
{
    std::vector<std::string> parts;
    if (!ids || !gGetLangText)
        return parts;

    for (int i = 0; i < 5; ++i)
    {
        const uint64_t id = ids[i];
        if (IsEmptyStrCode64(id))
            break;

        const char* s = gGetLangText(id);
        if (!s)
            break;

        parts.emplace_back(s);
    }

    return parts;
}

/* Reverses breadcrumb order for Arabic. Params: parts = localized breadcrumb parts. */
static std::string JoinArabicBreadcrumbReversed(const std::vector<std::string>& parts)
{
    if (parts.empty())
        return std::string();

    std::string out;
    for (size_t i = parts.size(); i-- > 0; )
    {
        if (!out.empty())
            out += " < ";
        out += parts[i];
    }

    return out;
}

/* Rebuilds +0x7CA segment lengths for Arabic breadcrumb. Params: thisPtr = MbTitleEv, parts = localized parts. */
static void RebuildSegmentLengthsArabic(void* thisPtr, const std::vector<std::string>& parts)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    auto* lens = reinterpret_cast<uint16_t*>(base + 0x7CA);

    for (int i = 0; i < 5; ++i)
        lens[i] = 0;

    if (parts.empty())
        return;

    std::string running = parts.back();
    lens[0] = 0;

    size_t markerIndex = 1;
    for (size_t revIndex = parts.size(); revIndex-- > 1 && markerIndex < 5; )
    {
        running += " < ";
        lens[markerIndex] = static_cast<uint16_t>(Utf8CharLen(running.c_str()));
        running += parts[revIndex - 1];
        ++markerIndex;
    }

    const uint16_t lastVal = lens[(markerIndex == 0) ? 0 : (markerIndex - 1)];
    while (markerIndex < 5)
    {
        lens[markerIndex] = lastVal;
        ++markerIndex;
    }
}

/* Rebuilds typed buffer at +0x11B9 from the end for Arabic. Params: thisPtr = MbTitleEv. */
static void RebuildArabicTypingBuffer(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    char* fullBuf = reinterpret_cast<char*>(base + 0x10B9);
    char* typedBuf = reinterpret_cast<char*>(base + 0x11B9);

    uint8_t isTyping = 0;
    uint16_t revealCount = 0;

    if (!SafeReadU8(base + 0x12D4, isTyping))
        return;
    if (!SafeReadU16(base + 0x12D0, revealCount))
        return;

    std::string visible = Utf8LogicalSuffix(fullBuf, revealCount);

    if (visible.empty() && revealCount != 0)
        visible = std::string(fullBuf);

    if (isTyping)
        visible = "_" + visible;

    SafeWriteCString(typedBuf, 0x100, visible.c_str());
}

/* Forces title node alignment to right. Params: thisPtr = MbTitleEv. */
static void ForceRightAlignOnTitleNode(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* titleNode = nullptr;
    if (!SafeReadPtr(base + 0x13E0, titleNode) || !titleNode)
        return;

    SafeWriteU8(reinterpret_cast<uint8_t*>(titleNode) + 0xD8, TEXT_ALIGN_RIGHT);
}

/* Applies Arabic breadcrumb rebuild after original function. Params: thisPtr = MbTitleEv, ids = breadcrumb StrCode64 array. */
static void ApplyArabicBreadcrumbFix(void* thisPtr, uint64_t* ids)
{
    if (!thisPtr || !ids || !gGetLangText || !gSetTextForModelNodeText)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    const std::vector<std::string> parts = CollectLocalizedParts(ids);
    if (parts.empty())
        return;

    const std::string fullArabic = JoinArabicBreadcrumbReversed(parts);

    char* fullBuf = reinterpret_cast<char*>(base + 0x10B9);
    char* typedBuf = reinterpret_cast<char*>(base + 0x11B9);

    SafeWriteCString(fullBuf, 0x100, fullArabic.c_str());
    RebuildSegmentLengthsArabic(thisPtr, parts);
    RebuildArabicTypingBuffer(thisPtr);
    ForceRightAlignOnTitleNode(thisPtr);

    void* titleNode = nullptr;
    if (!SafeReadPtr(base + 0x13E0, titleNode) || !titleNode)
        return;

    void* textUnit = base + 0x7D8;
    gSetTextForModelNodeText(titleNode, textUnit, typedBuf, 1);

    ForceRightAlignOnTitleNode(thisPtr);
}

/* Hook for MbTitleEv::SetMenuNameText. Params: thisPtr = MbTitleEv, ids = breadcrumb StrCode64 array. */
static void __fastcall hkSetMenuNameText(void* thisPtr, uint64_t* ids)
{
    if (gOrigSetMenuNameText)
        gOrigSetMenuNameText(thisPtr, ids);

    if (!IsArabicSafe())
        return;

    ApplyArabicBreadcrumbFix(thisPtr, ids);
}

/* Installs MbTitleEv::SetMenuNameText Arabic hook. Params: hGame = game module handle. */
bool InstallMbTitleEvSetMenuNameTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.SetMenuNameText || !gAddr.GetLangText || !gAddr.SetTextForModelNodeText)
    {
        Log("[MbTitleEv::SetMenuNameText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gGetLangText = reinterpret_cast<GetLangText_t>(gAddr.GetLangText);
    gSetTextForModelNodeText = reinterpret_cast<SetTextForModelNodeText_t>(gAddr.SetTextForModelNodeText);
    gTarget = reinterpret_cast<void*>(gAddr.SetMenuNameText);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkSetMenuNameText,
        reinterpret_cast<LPVOID*>(&gOrigSetMenuNameText)) != MH_OK)
    {
        Log("[MbTitleEv::SetMenuNameText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[MbTitleEv::SetMenuNameText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[MbTitleEv::SetMenuNameText] Arabic hook enabled.\n");
    return true;
}

/* Removes MbTitleEv::SetMenuNameText Arabic hook. Params: none. */
void RemoveMbTitleEvSetMenuNameTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigSetMenuNameText = nullptr;
    gGetLangText = nullptr;
    gSetTextForModelNodeText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[MbTitleEv::SetMenuNameText] Arabic hook removed.\n");
}