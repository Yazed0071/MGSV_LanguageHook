// HeadMarkMarker_SetMarkerText_ArabicFix.cpp

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdio>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

typedef bool(__cdecl* IsArabLanguage_t)();
static IsArabLanguage_t IsArabLanguage = nullptr;

// ------------------------------------------------------------
// Absolute addresses
// ------------------------------------------------------------
static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

// Lang IDs from your function
static constexpr uint64_t LANGID_MARKER_C9 = 0x7A079E6E4016ull;
static constexpr uint64_t LANGID_MARKER_C7 = 0x7236B243ADDFull;
static constexpr uint64_t LANGID_MARKER_C8 = 0xDB3F8095A297ull;

// ------------------------------------------------------------

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return (uintptr_t)hGame + (absVa - IDA_IMAGE_BASE);
}

static __forceinline bool IsArabicSafe()
{
    if (!IsArabLanguage)
        return false;

    __try
    {
        return IsArabLanguage();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

// ------------------------------------------------------------
// Game function typedefs
// ------------------------------------------------------------

using SetMarkerText_t = void(__fastcall*)(
    void* owner,
    void* markerObj,
    void* param3,
    uint64_t param4,
    char param5,
    char param6);

using GetLangText_t = const char* (__fastcall*)(uint64_t langId);
using SetTextForModelNodeText_t = void(__fastcall*)(void* modelNodeText, void* textUnit, const char* text, uint8_t flag);

static SetMarkerText_t oSetMarkerText = nullptr;
static GetLangText_t gGetLangText = nullptr;
static SetTextForModelNodeText_t gSetTextForModelNodeText = nullptr;

static void* gTarget = nullptr;

static std::unordered_map<void*, std::string> gMarkerBuf;
static std::mutex gMarkerMtx;

// ------------------------------------------------------------
// UTF-8 helpers
// ------------------------------------------------------------

static inline bool Utf8IsLeadByte(unsigned char c)
{
    return (c & 0xC0) != 0x80;
}

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

    offsets.push_back(i); // end sentinel
    return offsets;
}

static std::string Utf8LogicalSuffix(const char* s, size_t charCountFromEnd)
{
    if (!s || !*s)
        return std::string();

    std::vector<size_t> offsets = Utf8CharOffsets(s);
    if (offsets.size() < 2)
        return std::string();

    const size_t totalChars = offsets.size() - 1;
    if (charCountFromEnd == 0)
        return std::string();

    if (charCountFromEnd >= totalChars)
        return std::string(s);

    const size_t startChar = totalChars - charCountFromEnd;
    const size_t startByte = offsets[startChar];
    const size_t endByte = offsets[totalChars];

    return std::string(s + startByte, endByte - startByte);
}

// ------------------------------------------------------------
// Safe helpers
// ------------------------------------------------------------

static bool SafeReadPtr(const void* addr, void*& out)
{
    __try
    {
        out = *reinterpret_cast<void* const*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool SafeReadU8(const void* addr, uint8_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint8_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
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

        std::snprintf(dst, dstSize, "%s", src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

// ------------------------------------------------------------
// Rebuild logic
// ------------------------------------------------------------

static std::string BuildFullMarkerText(void* markerObj)
{
    if (!markerObj || !gGetLangText)
        return std::string();

    auto* base = reinterpret_cast<uint8_t*>(markerObj);

    uint8_t c7 = 0;
    uint8_t c8 = 0;
    uint8_t c9 = 0;
    uint8_t dist = 0;

    if (!SafeReadU8(base + 0xC7, c7)) return std::string();
    if (!SafeReadU8(base + 0xC8, c8)) return std::string();
    if (!SafeReadU8(base + 0xC9, c9)) return std::string();
    if (!SafeReadU8(base + 0xE0, dist)) return std::string();

    if (c9)
    {
        const char* s = gGetLangText(LANGID_MARKER_C9);
        return s ? std::string(s) : std::string();
    }

    if (c7)
    {
        const char* s = gGetLangText(LANGID_MARKER_C7);
        return s ? std::string(s) : std::string();
    }

    if (c8)
    {
        const char* s = gGetLangText(LANGID_MARKER_C8);
        return s ? std::string(s) : std::string();
    }

    char buf[0x36] = {};
    std::snprintf(buf, sizeof(buf), "%u%s", static_cast<unsigned>(dist), "\xD9\x85"); // "\xD9\x85" = "م"
    return std::string(buf);
}

static void FixArabicMarkerReveal(void* owner, void* markerObj)
{
    if (!owner || !markerObj || !gSetTextForModelNodeText)
        return;

    auto* base = reinterpret_cast<uint8_t*>(markerObj);

    void* nodeA = nullptr;
    void* nodeB = nullptr;

    if (!SafeReadPtr(base + 0x98, nodeA) || !nodeA)
        return;
    if (!SafeReadPtr(base + 0xA0, nodeB) || !nodeB)
        return;

    uint8_t revealCount = 0;
    if (!SafeReadU8(base + 0xC1, revealCount))
        return;

    std::string fullText = BuildFullMarkerText(markerObj);
    if (fullText.empty())
        return;

    std::string visibleText = Utf8LogicalSuffix(fullText.c_str(), revealCount);
    if (visibleText.empty() && revealCount != 0)
        visibleText = fullText;

    char* outBuf = reinterpret_cast<char*>(base + 0xE1);
    SafeWriteCString(outBuf, 0x36, visibleText.c_str());

    const char* textPtr = nullptr;
    {
        std::lock_guard<std::mutex> lk(gMarkerMtx);
        std::string& stored = gMarkerBuf[markerObj];
        stored.assign(visibleText);
        textPtr = stored.c_str();
    }

    void* textUnit = reinterpret_cast<uint8_t*>(owner) + 0xF8;

    gSetTextForModelNodeText(nodeA, textUnit, textPtr, 1);
    gSetTextForModelNodeText(nodeB, textUnit, textPtr, 1);
}

// ------------------------------------------------------------
// Hook
// ------------------------------------------------------------

static void __fastcall hkSetMarkerText(
    void* owner,
    void* markerObj,
    void* param3,
    uint64_t param4,
    char param5,
    char param6)
{
    if (oSetMarkerText)
        oSetMarkerText(owner, markerObj, param3, param4, param5, param6);

    if (!IsArabicSafe())
        return;

    FixArabicMarkerReveal(owner, markerObj);
}

// ------------------------------------------------------------
// Install / remove
// ------------------------------------------------------------

bool InstallHeadMarkMarkerEvCallSetMarkerTextArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    IsArabLanguage = reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));
    gGetLangText = reinterpret_cast<GetLangText_t>(ToRuntimeVA(hGame, gAddr.GetLangText));
    gSetTextForModelNodeText =
        reinterpret_cast<SetTextForModelNodeText_t>(ToRuntimeVA(hGame, gAddr.SetTextForModelNodeText));

    gTarget = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetMarkerText));
    if (!gTarget)
        return false;

    if (MH_CreateHook(gTarget, &hkSetMarkerText, reinterpret_cast<LPVOID*>(&oSetMarkerText)) != MH_OK)
    {
        Log("[HeadMarkMarker::SetMarkerText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[HeadMarkMarker::SetMarkerText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[HeadMarkMarker::SetMarkerText] Arabic fix hook enabled.\n");
    return true;
}

void RemoveHeadMarkMarkerEvCallSetMarkerTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    oSetMarkerText = nullptr;
    gGetLangText = nullptr;
    gSetTextForModelNodeText = nullptr;

    {
        std::lock_guard<std::mutex> lk(gMarkerMtx);
        gMarkerBuf.clear();
    }

    Log("[HeadMarkMarker::SetMarkerText] Removed.\n");
}