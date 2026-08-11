#include <windows.h>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <intrin.h>

#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

using IsArabLanguage_t  = bool(__cdecl*)();
using ScrollDriver_t    = void(__fastcall*)(void* node, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7);
using GetDisplayWidth_t = float(__fastcall*)(void* node);
using SetAutoScroll_t   = bool(__fastcall*)(void* node, void* unit, const char* text);
using UseAutoScroll_t   = void(__fastcall*)(void* node, void* unit, const char* text);
using SettingScroll_t   = char(__fastcall*)(void* node, void* unit, const char* text);
using SetTrack_t        = void(__fastcall*)(void* thisPtr, void* a2, void* a3, void* unit);
using CassetteCtor_t    = void*(__fastcall*)(void* thisPtr);
using CassetteDtor_t    = void(__fastcall*)(void* thisPtr, void* a2, void* a3, void* a4);
using RowText_t         = void(__fastcall*)(void* record);
using PlayerPanel_t     = void(__fastcall*)(void* self, int ev, unsigned __int64 mask);
using TaskRow_t         = void(__fastcall*)(void* self, void* param2);
using IconInfo_t        = void(__fastcall*)(void* self);
using EquipDetails_t    = void(__fastcall*)(void* self);

static IsArabLanguage_t  gIsArab         = nullptr;
static ScrollDriver_t    oScrollDriver   = nullptr;
static GetDisplayWidth_t gGetDisplayW    = nullptr;
static SetAutoScroll_t   oSetAutoScroll  = nullptr;
static UseAutoScroll_t   oUseAutoScroll  = nullptr;
static SettingScroll_t   oSettingScroll  = nullptr;
static SetTrack_t        oSetTrack       = nullptr;
static CassetteCtor_t    oCassetteCtor   = nullptr;
static CassetteDtor_t    oCassetteDtor   = nullptr;
static RowText_t         oTapeRowText    = nullptr;
static RowText_t         oTrackRowText   = nullptr;
static PlayerPanel_t     oPlayerPanel    = nullptr;
static TaskRow_t         oMissionTaskRow = nullptr;
static TaskRow_t         oMissionTaskRow2 = nullptr;
static IconInfo_t        oUpdateIconInfo = nullptr;
static EquipDetails_t    oEquipDetails    = nullptr;

static void* gTargetDriver        = nullptr;
static void* gTargetSetAuto       = nullptr;
static void* gTargetUseAuto       = nullptr;
static void* gTargetSettingScroll = nullptr;
static void* gTargetSetTrack      = nullptr;
static void* gTargetCassetteCtor  = nullptr;
static void* gTargetCassetteDtor  = nullptr;
static void* gTargetTapeRow        = nullptr;
static void* gTargetTrackRow       = nullptr;
static void* gTargetPlayerPanel    = nullptr;
static void* gTargetMissionTaskRow = nullptr;
static void* gTargetMissionTaskRow2 = nullptr;
static void* gTargetUpdateIconInfo = nullptr;
static void* gTargetEquipDetails    = nullptr;

static std::atomic<int> gCassetteListDepth{ 0 };

static constexpr uintptr_t IDA_IMAGE_BASE   = 0x140000000ull;
static constexpr size_t    OFF_SCROLL_STATE = 0x92;
static constexpr size_t    OFF_SCROLL_POS   = 0x1B4;
static constexpr size_t    OFF_TEXT_WIDTH   = 0x17C;
static constexpr size_t    OFF_ALIGN        = 0xD8;
static constexpr size_t    OFF_ALIGN_DRIVER = 0xDA;
static constexpr uint8_t   ALIGN_RIGHT      = 2;
static constexpr size_t    OFF_ROW_NODE     = 0x98;
static constexpr size_t    OFF_PANEL_TITLE  = 0xF8;
static constexpr size_t    OFF_PANEL_SUB    = 0xF0;
static constexpr size_t    OFF_TASK_NODE    = 0x60;

static std::unordered_map<void*, float> gRtl;
static std::mutex gRtlMtx;

using SetText_t = void(__fastcall*)(void*, void*, const char*, uint64_t);
static SetText_t oSetText = nullptr;
static void* gTargetSetText = nullptr;

static void HandleTitleNode(void* node, const char* text);

static bool IsTaskTitleText(const char* text)
{
    static const unsigned char pat[13] = {
        0xD9, 0x85, 0xD9, 0x87, 0xD8, 0xA7, 0xD9, 0x85, 0x20, 0xD8, 0xA7, 0xD9, 0x84 };
    __try
    {
        const unsigned char* s = reinterpret_cast<const unsigned char*>(text);
        if (!s) return false;
        for (int i = 0; i < 13; ++i)
            if (s[i] != pat[i]) return false;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}


static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

static bool IsArabicSafe()
{
    if (!gIsArab)
        return false;

    __try { return gIsArab(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool SafeReadF(const void* addr, float& out)
{
    __try { out = *reinterpret_cast<const float*>(addr); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { out = 0.0f; return false; }
}

static bool SafeReadU8(const void* addr, uint8_t& out)
{
    __try { out = *reinterpret_cast<const uint8_t*>(addr); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { out = 0; return false; }
}

static bool SafeWriteF(void* addr, float value)
{
    __try { *reinterpret_cast<float*>(addr) = value; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool SafeReadPtr(const void* addr, void*& out)
{
    __try { out = *reinterpret_cast<void* const*>(addr); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { out = nullptr; return false; }
}

static bool SafeReadU32(const void* addr, uint32_t& out)
{
    __try { out = *reinterpret_cast<const uint32_t*>(addr); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { out = 0; return false; }
}

static bool SafeWriteU8(void* addr, uint8_t value)
{
    __try { *reinterpret_cast<uint8_t*>(addr) = value; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool NextUtf8Codepoint(const char*& s, uint32_t& cp)
{
    if (!s || !*s)
        return false;

    const unsigned char c0 = static_cast<unsigned char>(*s++);

    if (c0 < 0x80) { cp = c0; return true; }

    if ((c0 >> 5) == 0x6)
    {
        if (!*s) { cp = c0; return true; }
        const unsigned char c1 = static_cast<unsigned char>(*s++);
        cp = ((c0 & 0x1F) << 6) | (c1 & 0x3F);
        return true;
    }

    if ((c0 >> 4) == 0xE)
    {
        if (!s[0] || !s[1]) { cp = c0; return true; }
        const unsigned char c1 = static_cast<unsigned char>(*s++);
        const unsigned char c2 = static_cast<unsigned char>(*s++);
        cp = ((c0 & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F);
        return true;
    }

    if ((c0 >> 3) == 0x1E)
    {
        if (!s[0] || !s[1] || !s[2]) { cp = c0; return true; }
        const unsigned char c1 = static_cast<unsigned char>(*s++);
        const unsigned char c2 = static_cast<unsigned char>(*s++);
        const unsigned char c3 = static_cast<unsigned char>(*s++);
        cp = ((c0 & 0x07) << 18) | ((c1 & 0x3F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
        return true;
    }

    cp = c0;
    return true;
}

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

static bool ContainsArabicSafe(const char* text)
{
    __try { return ContainsArabicUtf8(text); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static constexpr size_t OFF_UNIT_ARRAY = 0x138;
static constexpr size_t OFF_UNIT_COUNT = 0x140;
static constexpr size_t UNIT_STRIDE    = 0x20;

static bool NodeTextIsArabic(void* node)
{
    void* unitArray = nullptr;
    if (!SafeReadPtr(reinterpret_cast<char*>(node) + OFF_UNIT_ARRAY, unitArray) || !unitArray)
        return false;

    uint32_t count = 0;
    SafeReadU32(reinterpret_cast<char*>(node) + OFF_UNIT_COUNT, count);
    if (count == 0) count = 1;
    if (count > 64) count = 64;

    for (uint32_t i = 0; i < count; ++i)
    {
        void* text = nullptr;
        if (!SafeReadPtr(reinterpret_cast<char*>(unitArray) + static_cast<size_t>(i) * UNIT_STRIDE, text))
            break;
        if (text && ContainsArabicSafe(reinterpret_cast<const char*>(text)))
            return true;
    }
    return false;
}

static void StampNode(void* node, const char* text)
{
    if (!node)
        return;

    const bool rtl = IsArabicSafe() && ContainsArabicSafe(text);

    std::lock_guard<std::mutex> lk(gRtlMtx);
    if (rtl)
        gRtl[node] = 0.0f;
    else
        gRtl.erase(node);
}

static void __fastcall hkScrollDriver(void* node, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7)
{

    if (!node)
    {
        oScrollDriver(node, a2, a3, a4, a5, a6, a7);
        return;
    }

    uint8_t state = 0;
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_SCROLL_STATE, state);

    const bool cassetteActive = (gCassetteListDepth.load() > 0) && IsArabicSafe();

    bool  isRtl      = false;
    bool  haveShadow = false;
    float shadow     = 0.0f;
    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        auto it = gRtl.find(node);
        if (it != gRtl.end())
        {
            isRtl      = true;
            haveShadow = true;
            shadow     = it->second;
        }
    }

    if (!isRtl && state != 0 && IsArabicSafe() &&
        (cassetteActive || NodeTextIsArabic(node)))
        isRtl = true;

    if (!isRtl && !cassetteActive)
    {
        oScrollDriver(node, a2, a3, a4, a5, a6, a7);
        return;
    }

    float* pos = reinterpret_cast<float*>(reinterpret_cast<char*>(node) + OFF_SCROLL_POS);

    if (isRtl && state == 2 && haveShadow)
        SafeWriteF(pos, shadow);

    oScrollDriver(node, a2, a3, a4, a5, a6, a7);

    if (cassetteActive)
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, ALIGN_RIGHT);

    if (!isRtl)
        return;

    float s = 0.0f;
    SafeReadF(pos, s);

    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        gRtl[node] = s;
    }

    float W = 0.0f;
    if (gGetDisplayW)
        W = gGetDisplayW(node);

    float T = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, T);

    if (W > 0.0f && T > W)
        SafeWriteF(pos, (T - W) - s);
}

static bool __fastcall hkSetAutoScroll(void* node, void* unit, const char* text)
{
    const bool overflow = oSetAutoScroll(node, unit, text);
    StampNode(node, text);
    HandleTitleNode(node, text);
    return overflow;
}

static void __fastcall hkUseAutoScroll(void* node, void* unit, const char* text)
{
    oUseAutoScroll(node, unit, text);
    StampNode(node, text);
    HandleTitleNode(node, text);
}

static void StampNodeArabic(void* node, const char* text)
{
    if (!node)
        return;
    if (!(IsArabicSafe() && ContainsArabicSafe(text)))
        return;

    std::lock_guard<std::mutex> lk(gRtlMtx);
    gRtl[node] = 0.0f;
}

static char __fastcall hkSettingTextUnitForScroll(void* node, void* unit, const char* text)
{
    const char overflow = oSettingScroll(node, unit, text);
    StampNodeArabic(node, text);
    HandleTitleNode(node, text);
    return overflow;
}

static void __fastcall hkSetTrack(void* thisPtr, void* a2, void* a3, void* unit)
{
    oSetTrack(thisPtr, a2, a3, unit);

    if (!thisPtr || !IsArabicSafe())
        return;

    void* node = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(thisPtr) + 0x10, node) && node)
    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        gRtl[node] = 0.0f;
    }
}

static void* __fastcall hkCassetteCtor(void* thisPtr)
{
    void* r = oCassetteCtor(thisPtr);
    gCassetteListDepth.fetch_add(1);
    return r;
}

static void __fastcall hkCassetteDtor(void* thisPtr, void* a2, void* a3, void* a4)
{
    if (gCassetteListDepth.load() > 0)
        gCassetteListDepth.fetch_sub(1);
    oCassetteDtor(thisPtr, a2, a3, a4);
}

static void ForceNodeRightAlignIfFits(void* node)
{
    if (!node)
        return;

    float T = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, T);

    float W = 0.0f;
    if (gGetDisplayW)
        W = gGetDisplayW(node);

    if (W > 0.0f && T > W)
    {
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, 0);
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, 3);
        return;
    }

    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, ALIGN_RIGHT);
    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, ALIGN_RIGHT);
}

static void ForceNodeRightAlignAlways(void* node)
{
    if (!node)
        return;

    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, ALIGN_RIGHT);
    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, ALIGN_RIGHT);
}

enum EquipNodeClass { EQUIP_UNKNOWN = 0, EQUIP_ARABIC = 1, EQUIP_LATIN = 2 };

static std::mutex gEquipClassMtx;
static std::unordered_map<void*, int> gEquipClass;
static std::unordered_map<void*, uint8_t> gEquipOrigAlign;

static void RememberOriginalAlign(void* node, uint8_t align)
{
    std::lock_guard<std::mutex> lk(gEquipClassMtx);
    if (gEquipOrigAlign.find(node) == gEquipOrigAlign.end())
        gEquipOrigAlign[node] = align;
}

static int GetEquipNodeClass(void* node)
{
    std::lock_guard<std::mutex> lk(gEquipClassMtx);
    auto it = gEquipClass.find(node);
    return it == gEquipClass.end() ? EQUIP_UNKNOWN : it->second;
}

static void SetEquipNodeClass(void* node, int cls)
{
    std::lock_guard<std::mutex> lk(gEquipClassMtx);
    gEquipClass[node] = cls;
}

static void RestoreEquipNodeVanilla(void* node)
{
    uint8_t orig = 0;
    {
        std::lock_guard<std::mutex> lk(gEquipClassMtx);
        auto it = gEquipOrigAlign.find(node);
        if (it == gEquipOrigAlign.end())
            return;
        orig = it->second;
    }

    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, orig);
    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, orig);

    std::lock_guard<std::mutex> lk(gRtlMtx);
    gRtl.erase(node);
}

static void HandleTitleNode(void* node, const char* text)
{
    if (!node || !IsArabicSafe() || !IsTaskTitleText(text))
        return;

    ForceNodeRightAlignIfFits(node);
}

static uintptr_t gDiagGameBase = 0;
static std::atomic<int> gTitleDiagBudget{ 60 };

static void DiagLogTitleText(const char* text, void* node, void* caller)
{
    __try
    {
        if (!text || !text[0])
            return;

        static const char kEquip[] = {
            (char)0xD8,(char)0xA7,(char)0xD9,(char)0x84,(char)0xD9,(char)0x85,(char)0xD8,(char)0xB9,
            (char)0xD8,(char)0xAF,(char)0xD8,(char)0xA7,(char)0xD8,(char)0xAA, 0 };
        if (!strstr(text, kEquip))
            return;

        if (gTitleDiagBudget.load() <= 0)
            return;
        gTitleDiagBudget.fetch_sub(1);

        uintptr_t va = 0;
        if (gDiagGameBase && caller)
            va = reinterpret_cast<uintptr_t>(caller) - gDiagGameBase + 0x140000000ull;

        Log("[TitleDiag] node=%p caller_va=0x%llx text=%s\n",
            node, (unsigned long long)va, text);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void __fastcall hkSetText(void* node, void* ctx, const char* text, uint64_t flag)
{
    void* caller = _ReturnAddress();
    oSetText(node, ctx, text, flag);
    HandleTitleNode(node, text);
    if (IsArabicSafe())
        DiagLogTitleText(text, node, caller);
}

static void ForceRowNameRightAlign(void* record)
{
    if (!record || !IsArabicSafe())
        return;

    void* node = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(record) + OFF_ROW_NODE, node) && node)
        ForceNodeRightAlignIfFits(node);
}

static void __fastcall hkTapeRowText(void* record)
{
    oTapeRowText(record);
    ForceRowNameRightAlign(record);
}

static void __fastcall hkTrackRowText(void* record)
{
    oTrackRowText(record);
    ForceRowNameRightAlign(record);
}

static void ForcePanelNodeRightAlign(void* self, size_t nodeOffset)
{
    void* node = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + nodeOffset, node) && node)
        ForceNodeRightAlignIfFits(node);
}

static void __fastcall hkUpdatePlayerPanel(void* self, int ev, unsigned __int64 mask)
{
    oPlayerPanel(self, ev, mask);

    if (!self || !IsArabicSafe())
        return;

    ForcePanelNodeRightAlign(self, OFF_PANEL_TITLE);
    ForcePanelNodeRightAlign(self, OFF_PANEL_SUB);
}

static void AlignTaskRow(void* self)
{
    if (!self || !IsArabicSafe())
        return;

    void* node = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + OFF_TASK_NODE, node) && node)
        ForceNodeRightAlignIfFits(node);
}

static void __fastcall hkMissionTaskRow(void* self, void* param2)
{
    oMissionTaskRow(self, param2);
    AlignTaskRow(self);
}

static void __fastcall hkMissionTaskRow2(void* self, void* param2)
{
    oMissionTaskRow2(self, param2);
    AlignTaskRow(self);
}

using IconSetText_t = void(__fastcall*)(void*, void*, void*, const char*, uint64_t);
using IconInfoEntry_t = uint64_t*(__fastcall*)(void* infoMgr, void* scratch, uint64_t index);
using IconInfoFlag_t = char(__fastcall*)(void* infoMgr, uint64_t index, uint64_t mask);
using IconGetLangText_t = const char*(__fastcall*)(void* uiObj, uint64_t langId);

static char gIconNameBuf[4][256];

static bool SwapTrailingParenGroup(char* buf, size_t cap)
{
    __try
    {
        const size_t maxLen = (cap == 0) ? 0 : cap - 1;
        size_t len = 0;
        while (len < maxLen && buf[len]) ++len;
        if (len < 3) return false;
        if (buf[0] == '(') return false;
        if (buf[len - 1] != ')') return false;

        size_t open = len;
        for (size_t i = len; i-- > 0; )
        {
            if (buf[i] == '(') { open = i; break; }
        }
        if (open == 0 || open == len) return false;

        char tmp[256];
        if (len + 1 > sizeof(tmp)) return false;
        const size_t statusLen = len - open;
        memcpy(tmp, buf + open, statusLen);
        memcpy(tmp + statusLen, buf, open);
        tmp[len] = '\0';
        memcpy(buf, tmp, len + 1);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool BuildFullIconName(void* uiObj, void* infoMgr, int index, char* out, size_t outCap)
{
    if (!uiObj || !infoMgr || !out || outCap == 0)
        return false;

    __try
    {
        void* uiVt = *reinterpret_cast<void**>(uiObj);
        void* infoVt = *reinterpret_cast<void**>(infoMgr);
        if (!uiVt || !infoVt)
            return false;

        auto fnEntry = *reinterpret_cast<IconInfoEntry_t*>(reinterpret_cast<char*>(infoVt) + 0xE8);
        auto fnLang = *reinterpret_cast<IconGetLangText_t*>(reinterpret_cast<char*>(uiVt) + 0x750);
        auto fnFlag = *reinterpret_cast<IconInfoFlag_t*>(reinterpret_cast<char*>(infoVt) + 0xF0);
        if (!fnEntry || !fnLang)
            return false;

        uint64_t scratch[2] = { 0, 0 };
        uint64_t* entry = fnEntry(infoMgr, scratch, static_cast<uint64_t>(index));
        if (!entry)
            return false;

        const char* name = fnLang(uiObj, *entry);
        if (!name || !*name)
            return false;

        size_t n = 0;
        while (n + 1 < outCap && name[n]) { out[n] = name[n]; ++n; }
        out[n] = '\0';

        if (fnFlag && fnFlag(infoMgr, static_cast<uint64_t>(index), 0x10))
        {
            const char* suffix = fnLang(uiObj, 0xCC728F2D7CE1ull);
            if (suffix)
            {
                size_t k = 0;
                while (n + 1 < outCap && suffix[k]) { out[n] = suffix[k]; ++n; ++k; }
                out[n] = '\0';
            }
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void RightAlignNode(void* node)
{
    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, ALIGN_RIGHT);
    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, ALIGN_RIGHT);
}

static void __fastcall hkUpdateIconInfo(void* self)
{
    oUpdateIconInfo(self);

    if (!self || !IsArabicSafe())
        return;

    void* layoutCtx = nullptr;
    void* uiObj = nullptr;
    void* ctx = nullptr;
    void* infoMgr = nullptr;
    SafeReadPtr(reinterpret_cast<char*>(self) + 0x38, layoutCtx);
    if (layoutCtx) SafeReadPtr(reinterpret_cast<char*>(layoutCtx) + 0x20, uiObj);
    if (layoutCtx) SafeReadPtr(reinterpret_cast<char*>(layoutCtx) + 0x90, infoMgr);
    SafeReadPtr(reinterpret_cast<char*>(self) + 0x958, ctx);

    uint8_t lineCount = 0;
    SafeReadU8(reinterpret_cast<char*>(self) + 0x92B, lineCount);
    if (lineCount > 4) lineCount = 4;

    for (int i = 0; i < 4; ++i)
    {
        void* node = nullptr;
        if (!SafeReadPtr(reinterpret_cast<char*>(self) + 0x58 + i * 8, node) || !node)
            continue;

        bool applied = false;

        if (uiObj && infoMgr && i < lineCount &&
            BuildFullIconName(uiObj, infoMgr, i, gIconNameBuf[i], sizeof(gIconNameBuf[i])))
        {
            SwapTrailingParenGroup(gIconNameBuf[i], sizeof(gIconNameBuf[i]));
            __try
            {
                void* vtable = *reinterpret_cast<void**>(uiObj);
                auto setText = reinterpret_cast<IconSetText_t>(
                    *reinterpret_cast<void**>(reinterpret_cast<char*>(vtable) + 0x710));
                setText(uiObj, node, ctx, gIconNameBuf[i], 1);
                applied = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (!applied)
        {
            char* buf = reinterpret_cast<char*>(self) + 0xD8 + i * 0x40;
            if (uiObj && SwapTrailingParenGroup(buf, 0x40))
            {
                __try
                {
                    void* vtable = *reinterpret_cast<void**>(uiObj);
                    auto setText = reinterpret_cast<IconSetText_t>(
                        *reinterpret_cast<void**>(reinterpret_cast<char*>(vtable) + 0x710));
                    setText(uiObj, node, ctx, buf, 1);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }

        RightAlignNode(node);
    }

    void* heliName = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + 0x1D8, heliName) && heliName)
        RightAlignNode(heliName);

    void* heliDanger = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + 0x1E0, heliDanger) && heliDanger)
        RightAlignNode(heliDanger);
}

static bool NodeLooksLikeText(void* node)
{
    void* arr = nullptr;
    if (!SafeReadPtr(reinterpret_cast<char*>(node) + OFF_UNIT_ARRAY, arr) || !arr)
        return false;

    uint32_t count = 0;
    if (!SafeReadU32(reinterpret_cast<char*>(node) + OFF_UNIT_COUNT, count))
        return false;

    return count >= 1 && count <= 64;
}

static bool NodeIsConfirmedText(void* node)
{
    if (!NodeLooksLikeText(node))
        return false;

    uint8_t d8 = 0xFF;
    if (!SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, d8) || d8 > 3)
        return false;

    void* arr = nullptr;
    if (!SafeReadPtr(reinterpret_cast<char*>(node) + OFF_UNIT_ARRAY, arr) || !arr)
        return false;

    void* firstText = nullptr;
    if (!SafeReadPtr(arr, firstText) || !firstText)
        return false;

    uint8_t probe = 0;
    return SafeReadU8(firstText, probe);
}

static constexpr size_t kEquipDetailScanEnd = 0xE60;

static void NodeTextSurvey(void* node, bool& anyArabic, bool& anyNonEmpty, const char*& sample)
{
    anyArabic = false;
    anyNonEmpty = false;
    sample = nullptr;

    void* unitArray = nullptr;
    if (!SafeReadPtr(reinterpret_cast<char*>(node) + OFF_UNIT_ARRAY, unitArray) || !unitArray)
        return;

    uint32_t count = 0;
    SafeReadU32(reinterpret_cast<char*>(node) + OFF_UNIT_COUNT, count);
    if (count == 0) count = 1;
    if (count > 64) count = 64;

    for (uint32_t i = 0; i < count; ++i)
    {
        void* text = nullptr;
        if (!SafeReadPtr(reinterpret_cast<char*>(unitArray) + static_cast<size_t>(i) * UNIT_STRIDE, text))
            break;
        if (!text)
            continue;

        uint8_t first = 0;
        if (!SafeReadU8(text, first) || first == 0)
            continue;

        anyNonEmpty = true;
        if (!sample)
            sample = reinterpret_cast<const char*>(text);

        if (ContainsArabicSafe(reinterpret_cast<const char*>(text)))
        {
            anyArabic = true;
            return;
        }
    }
}

static std::atomic<int> gEquipDiagBudget{ 48 };
static std::atomic<int> gAmmoDiagBudget{ 700 };
static std::atomic<int> gEquipPassCounter{ 0 };


static void ForceStampRtlNode(void* node)
{
    if (!node)
        return;

    std::lock_guard<std::mutex> lk(gRtlMtx);
    if (gRtl.find(node) == gRtl.end())
        gRtl[node] = 0.0f;
}

static void __fastcall hkEquipDetails(void* self)
{
    oEquipDetails(self);

    if (!self || !IsArabicSafe())
        return;

    void* seen[192] = {};
    size_t seenCount = 0;

    const int pass = gEquipPassCounter.fetch_add(1);


    for (size_t off = 0; off < kEquipDetailScanEnd; off += sizeof(void*))
    {
        void* node = nullptr;
        if (!SafeReadPtr(reinterpret_cast<char*>(self) + off, node) || !node)
            continue;

        if (!NodeIsConfirmedText(node))
            continue;

        bool dup = false;
        for (size_t i = 0; i < seenCount; ++i)
        {
            if (seen[i] == node)
            {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;

        if (seenCount < _countof(seen))
            seen[seenCount++] = node;

        float T = 0.0f;
        SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, T);

        float W = 0.0f;
        if (gGetDisplayW)
            W = gGetDisplayW(node);

        uint8_t d8Before = 0xFF;
        SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, d8Before);
        RememberOriginalAlign(node, d8Before);

        bool anyArabic = false;
        bool anyNonEmpty = false;
        const char* sample = nullptr;
        NodeTextSurvey(node, anyArabic, anyNonEmpty, sample);

        if (anyArabic)
            SetEquipNodeClass(node, EQUIP_ARABIC);
        else if (anyNonEmpty)
            SetEquipNodeClass(node, EQUIP_LATIN);

        const int cls = GetEquipNodeClass(node);

        if (cls == EQUIP_ARABIC)
        {
            ForceNodeRightAlignIfFits(node);
            ForceStampRtlNode(node);
        }
        else if (cls == EQUIP_LATIN)
        {
            RestoreEquipNodeVanilla(node);
        }

        uint8_t d8After = 0xFF;
        SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, d8After);

        if (gAmmoDiagBudget.load() > 0)
        {
            gAmmoDiagBudget.fetch_sub(1);
            Log("[AmmoDiag] pass=%d off=0x%zX node=%p T=%.2f W=%.2f d8=%u->%u cls=%d\n",
                pass, off, node, T, W,
                static_cast<unsigned>(d8Before), static_cast<unsigned>(d8After), cls);
        }
    }

}

bool InstallArabicScrollReversalHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gDiagGameBase = reinterpret_cast<uintptr_t>(hGame);

    if (gAddr.SetTextForModelNodeText != 0)
    {
        gTargetSetText = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetTextForModelNodeText));
        if (gTargetSetText &&
            MH_CreateHook(gTargetSetText, &hkSetText,
                          reinterpret_cast<void**>(&oSetText)) == MH_OK &&
            MH_EnableHook(gTargetSetText) == MH_OK)
            Log("[ArabScroll] Task-title (SetText) right-align hook enabled.\n");
        else { Log("[ArabScroll] Task-title SetText hook failed.\n"); gTargetSetText = nullptr; }
    }

    if (gAddr.ModelNodeText_ScrollDriver == 0 ||
        gAddr.SetAutoScrollTextForModelNodeText == 0 ||
        gAddr.SetTextForModelNodeTextUseAutoScroll == 0)
    {
        Log("[ArabScroll] Addresses not set for this build; hook inactive.\n");
        return true;
    }

    gIsArab = reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));


    if (gAddr.ModelNodeText_GetDisplayWidth != 0)
        gGetDisplayW = reinterpret_cast<GetDisplayWidth_t>(
            ToRuntimeVA(hGame, gAddr.ModelNodeText_GetDisplayWidth));

    gTargetDriver  = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.ModelNodeText_ScrollDriver));
    gTargetSetAuto = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetAutoScrollTextForModelNodeText));
    gTargetUseAuto = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetTextForModelNodeTextUseAutoScroll));

    if (!gTargetDriver || !gTargetSetAuto || !gTargetUseAuto)
    {
        Log("[ArabScroll] Failed to resolve targets.\n");
        return false;
    }

    if (MH_CreateHook(gTargetDriver, &hkScrollDriver,
                      reinterpret_cast<void**>(&oScrollDriver)) != MH_OK)
    {
        Log("[ArabScroll] MH_CreateHook(driver) failed.\n");
        return false;
    }

    if (MH_CreateHook(gTargetSetAuto, &hkSetAutoScroll,
                      reinterpret_cast<void**>(&oSetAutoScroll)) != MH_OK)
    {
        Log("[ArabScroll] MH_CreateHook(SetAutoScroll) failed.\n");
        return false;
    }

    if (MH_CreateHook(gTargetUseAuto, &hkUseAutoScroll,
                      reinterpret_cast<void**>(&oUseAutoScroll)) != MH_OK)
    {
        Log("[ArabScroll] MH_CreateHook(UseAutoScroll) failed.\n");
        return false;
    }

    if (MH_EnableHook(gTargetDriver)  != MH_OK ||
        MH_EnableHook(gTargetSetAuto) != MH_OK ||
        MH_EnableHook(gTargetUseAuto) != MH_OK)
    {
        Log("[ArabScroll] MH_EnableHook failed.\n");
        return false;
    }

    if (gAddr.SettingTextUnitForScroll != 0)
    {
        gTargetSettingScroll =
            reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SettingTextUnitForScroll));

        if (gTargetSettingScroll &&
            MH_CreateHook(gTargetSettingScroll, &hkSettingTextUnitForScroll,
                          reinterpret_cast<void**>(&oSettingScroll)) == MH_OK &&
            MH_EnableHook(gTargetSettingScroll) == MH_OK)
        {
            Log("[ArabScroll] SettingTextUnitForScroll stamp hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] SettingTextUnitForScroll hook failed.\n");
            gTargetSettingScroll = nullptr;
        }
    }

    if (gAddr.SetTrack != 0)
    {
        gTargetSetTrack = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetTrack));

        if (gTargetSetTrack &&
            MH_CreateHook(gTargetSetTrack, &hkSetTrack,
                          reinterpret_cast<void**>(&oSetTrack)) == MH_OK &&
            MH_EnableHook(gTargetSetTrack) == MH_OK)
        {
            Log("[ArabScroll] SetTrack (cassette) RTL hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] SetTrack hook failed.\n");
            gTargetSetTrack = nullptr;
        }
    }

    if (gAddr.CassetteListCtor != 0 && gAddr.CassetteListDtor != 0)
    {
        gTargetCassetteCtor = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.CassetteListCtor));
        gTargetCassetteDtor = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.CassetteListDtor));

        if (gTargetCassetteCtor && gTargetCassetteDtor &&
            MH_CreateHook(gTargetCassetteCtor, &hkCassetteCtor,
                          reinterpret_cast<void**>(&oCassetteCtor)) == MH_OK &&
            MH_CreateHook(gTargetCassetteDtor, &hkCassetteDtor,
                          reinterpret_cast<void**>(&oCassetteDtor)) == MH_OK &&
            MH_EnableHook(gTargetCassetteCtor) == MH_OK &&
            MH_EnableHook(gTargetCassetteDtor) == MH_OK)
        {
            Log("[ArabScroll] Cassette-list context hooks enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Cassette-list context hooks failed.\n");
            gTargetCassetteCtor = nullptr;
            gTargetCassetteDtor = nullptr;
        }
    }

    if (gAddr.MbDvcTapeListRecordText != 0)
    {
        gTargetTapeRow = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.MbDvcTapeListRecordText));
        if (gTargetTapeRow &&
            MH_CreateHook(gTargetTapeRow, &hkTapeRowText,
                          reinterpret_cast<void**>(&oTapeRowText)) == MH_OK &&
            MH_EnableHook(gTargetTapeRow) == MH_OK)
        {
            Log("[ArabScroll] Tape-list row right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Tape-list row hook failed.\n");
            gTargetTapeRow = nullptr;
        }
    }

    if (gAddr.MbDvcTrackListRecordText != 0)
    {
        gTargetTrackRow = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.MbDvcTrackListRecordText));
        if (gTargetTrackRow &&
            MH_CreateHook(gTargetTrackRow, &hkTrackRowText,
                          reinterpret_cast<void**>(&oTrackRowText)) == MH_OK &&
            MH_EnableHook(gTargetTrackRow) == MH_OK)
        {
            Log("[ArabScroll] Track-list row right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Track-list row hook failed.\n");
            gTargetTrackRow = nullptr;
        }
    }

    if (gAddr.CassetteUpdatePlayerPanel != 0)
    {
        gTargetPlayerPanel = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.CassetteUpdatePlayerPanel));
        if (gTargetPlayerPanel &&
            MH_CreateHook(gTargetPlayerPanel, &hkUpdatePlayerPanel,
                          reinterpret_cast<void**>(&oPlayerPanel)) == MH_OK &&
            MH_EnableHook(gTargetPlayerPanel) == MH_OK)
        {
            Log("[ArabScroll] Cassette player-panel title right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Cassette player-panel hook failed.\n");
            gTargetPlayerPanel = nullptr;
        }
    }

    if (gAddr.MissionTaskRowUpdate != 0)
    {
        gTargetMissionTaskRow = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.MissionTaskRowUpdate));
        if (gTargetMissionTaskRow &&
            MH_CreateHook(gTargetMissionTaskRow, &hkMissionTaskRow,
                          reinterpret_cast<void**>(&oMissionTaskRow)) == MH_OK &&
            MH_EnableHook(gTargetMissionTaskRow) == MH_OK)
        {
            Log("[ArabScroll] Mission-task row right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Mission-task row hook failed.\n");
            gTargetMissionTaskRow = nullptr;
        }
    }

    if (gAddr.MissionTaskRowUpdate2 != 0)
    {
        gTargetMissionTaskRow2 = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.MissionTaskRowUpdate2));
        if (gTargetMissionTaskRow2 &&
            MH_CreateHook(gTargetMissionTaskRow2, &hkMissionTaskRow2,
                          reinterpret_cast<void**>(&oMissionTaskRow2)) == MH_OK &&
            MH_EnableHook(gTargetMissionTaskRow2) == MH_OK)
        {
            Log("[ArabScroll] Mission-task row (prep) right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Mission-task row (prep) hook failed.\n");
            gTargetMissionTaskRow2 = nullptr;
        }
    }

    if (gAddr.UpdateIconInfo != 0)
    {
        gTargetUpdateIconInfo = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.UpdateIconInfo));
        if (gTargetUpdateIconInfo &&
            MH_CreateHook(gTargetUpdateIconInfo, &hkUpdateIconInfo,
                          reinterpret_cast<void**>(&oUpdateIconInfo)) == MH_OK &&
            MH_EnableHook(gTargetUpdateIconInfo) == MH_OK)
        {
            Log("[ArabScroll] Map icon-info (LZ callout) right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Map icon-info hook failed.\n");
            gTargetUpdateIconInfo = nullptr;
        }
    }

    if (gAddr.EquipDetailsSetupDetails != 0)
    {
        gTargetEquipDetails = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.EquipDetailsSetupDetails));
        if (gTargetEquipDetails &&
            MH_CreateHook(gTargetEquipDetails, &hkEquipDetails,
                          reinterpret_cast<void**>(&oEquipDetails)) == MH_OK &&
            MH_EnableHook(gTargetEquipDetails) == MH_OK)
        {
            Log("[ArabScroll] Equip-details right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Equip-details hook failed.\n");
            gTargetEquipDetails = nullptr;
        }
    }

    Log("[ArabScroll] Arabic RTL marquee hooks enabled.\n");
    return true;
}

void RemoveArabicScrollReversalHook()
{
    if (gTargetDriver)  { MH_DisableHook(gTargetDriver);  MH_RemoveHook(gTargetDriver);  gTargetDriver  = nullptr; }
    if (gTargetSetAuto) { MH_DisableHook(gTargetSetAuto); MH_RemoveHook(gTargetSetAuto); gTargetSetAuto = nullptr; }
    if (gTargetUseAuto) { MH_DisableHook(gTargetUseAuto); MH_RemoveHook(gTargetUseAuto); gTargetUseAuto = nullptr; }
    if (gTargetSettingScroll) { MH_DisableHook(gTargetSettingScroll); MH_RemoveHook(gTargetSettingScroll); gTargetSettingScroll = nullptr; }
    if (gTargetSetTrack) { MH_DisableHook(gTargetSetTrack); MH_RemoveHook(gTargetSetTrack); gTargetSetTrack = nullptr; }
    if (gTargetCassetteCtor) { MH_DisableHook(gTargetCassetteCtor); MH_RemoveHook(gTargetCassetteCtor); gTargetCassetteCtor = nullptr; }
    if (gTargetCassetteDtor) { MH_DisableHook(gTargetCassetteDtor); MH_RemoveHook(gTargetCassetteDtor); gTargetCassetteDtor = nullptr; }
    if (gTargetTapeRow) { MH_DisableHook(gTargetTapeRow); MH_RemoveHook(gTargetTapeRow); gTargetTapeRow = nullptr; }
    if (gTargetTrackRow) { MH_DisableHook(gTargetTrackRow); MH_RemoveHook(gTargetTrackRow); gTargetTrackRow = nullptr; }
    if (gTargetPlayerPanel) { MH_DisableHook(gTargetPlayerPanel); MH_RemoveHook(gTargetPlayerPanel); gTargetPlayerPanel = nullptr; }
    if (gTargetMissionTaskRow) { MH_DisableHook(gTargetMissionTaskRow); MH_RemoveHook(gTargetMissionTaskRow); gTargetMissionTaskRow = nullptr; }
    if (gTargetMissionTaskRow2) { MH_DisableHook(gTargetMissionTaskRow2); MH_RemoveHook(gTargetMissionTaskRow2); gTargetMissionTaskRow2 = nullptr; }
    if (gTargetUpdateIconInfo) { MH_DisableHook(gTargetUpdateIconInfo); MH_RemoveHook(gTargetUpdateIconInfo); gTargetUpdateIconInfo = nullptr; }
    if (gTargetEquipDetails) { MH_DisableHook(gTargetEquipDetails); MH_RemoveHook(gTargetEquipDetails); gTargetEquipDetails = nullptr; }
    if (gTargetSetText) { MH_DisableHook(gTargetSetText); MH_RemoveHook(gTargetSetText); gTargetSetText = nullptr; }

    oScrollDriver  = nullptr;
    oSetAutoScroll = nullptr;
    oUseAutoScroll = nullptr;
    oSettingScroll = nullptr;
    oSetTrack      = nullptr;
    oCassetteCtor  = nullptr;
    oCassetteDtor  = nullptr;
    oTapeRowText   = nullptr;
    oTrackRowText  = nullptr;
    oPlayerPanel   = nullptr;
    oMissionTaskRow = nullptr;
    oMissionTaskRow2 = nullptr;
    oUpdateIconInfo = nullptr;
    oEquipDetails  = nullptr;
    oSetText       = nullptr;
    gGetDisplayW   = nullptr;
    gIsArab        = nullptr;
    gCassetteListDepth.store(0);

    std::lock_guard<std::mutex> lk(gRtlMtx);
    gRtl.clear();

    {
        std::lock_guard<std::mutex> lk(gEquipClassMtx);
        gEquipClass.clear();
        gEquipOrigAlign.clear();
    }
}
