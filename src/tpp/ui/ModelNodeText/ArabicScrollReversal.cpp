#include <windows.h>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <string>
#include <intrin.h>

#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

void CountTextUnitBuildsOnThisThread(uint32_t& all, uint32_t& arabic);
void* GetModelNodeTextVtable();
void KeepArabicLinesRightAlignedWhileShown(void* node, uint32_t leaseMs);
const char* ArabicRadioFileLabel(const char* text);
const char* FullArabicLabelForShortenedBuffer(const char* buffer);

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
using StaffRowName_t   = void(__fastcall*)(void* record, void* staff, uint64_t a3, uint64_t a4, uint64_t a5,
                                             uint64_t a6, uint64_t a7);
using SectionInfoText_t = uint64_t(__fastcall*)(void* self, void* record);
using StaffDetails_t    = void(__fastcall*)(void* self);
using BaseFacilityInfo_t = void(__fastcall*)(void* self);
using ResourceInfo_t    = void(__fastcall*)(void* self);
using AnnouncePopupStart_t = void(__fastcall*)(void* self, void* owner);
using UpdatePopup_t     = void(__fastcall*)(void* self);
using PrefabTextCallFunc_t = void(__fastcall*)(void* self, void* owner);
using UixSetTextImpl_t  = uint64_t(__fastcall*)(void* node, void* unit, const char* text, uint64_t a4, uint64_t a5);
using LookupByHash_t    = uint64_t(__fastcall*)(void* obj, uint64_t hash);
using LookupModel_t     = uint64_t(__fastcall*)(void* obj, uint64_t index, uint64_t layout);
using LookupChild_t     = uint64_t(__fastcall*)(void* obj, uint64_t parent, uint64_t hash);

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
using AmmoBoxInfo_t = void(__fastcall*)(void* self);
static AmmoBoxInfo_t     oAmmoBoxInfo = nullptr;
static AmmoBoxInfo_t     oSideFobInfoUpdate = nullptr;
static TaskRow_t         oMissionTaskRow = nullptr;
static TaskRow_t         oMissionTaskRow2 = nullptr;
static IconInfo_t        oUpdateIconInfo = nullptr;
static EquipDetails_t    oEquipDetails    = nullptr;
static StaffRowName_t    oStaffRowName    = nullptr;
static SectionInfoText_t oSectionInfoText = nullptr;
static StaffDetails_t    oStaffDetails    = nullptr;
static BaseFacilityInfo_t oBaseFacilityInfo = nullptr;
static ResourceInfo_t    oResourceInfo    = nullptr;
static AnnouncePopupStart_t oAnnouncePopupStart = nullptr;
static UpdatePopup_t     oUpdatePopup     = nullptr;
static PrefabTextCallFunc_t oPrefabTextCallFunc = nullptr;
static UixSetTextImpl_t  oUixSetTextImpl  = nullptr;

static void* gTargetDriver        = nullptr;
static void* gTargetSetAuto       = nullptr;
static void* gTargetUseAuto       = nullptr;
static void* gTargetSettingScroll = nullptr;
static void* gTargetSetTrack      = nullptr;
static void* gTargetCassetteCtor  = nullptr;
static void* gTargetCassetteDtor  = nullptr;
static void* gTargetTapeRow        = nullptr;
static void* gTargetTrackRow       = nullptr;
static void* gTargetStaffRowName   = nullptr;
static void* gTargetSectionInfo    = nullptr;
static void* gTargetStaffDetails   = nullptr;
static void* gTargetBaseFacilityInfo = nullptr;
static void* gTargetResourceInfo   = nullptr;
static uintptr_t* gAnnounceVtSlot  = nullptr;
static void* gTargetUpdatePopup    = nullptr;
static void* gTargetUixSetTextImpl = nullptr;
static void* gTargetPrefabTextCallFunc = nullptr;
static void* gTargetPlayerPanel    = nullptr;
static void* gTargetAmmoBoxInfo = nullptr;
static void* gTargetSideFobInfo = nullptr;
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
static constexpr size_t    OFF_SIDEFOB_NAME_A    = 0x40;
static constexpr size_t    OFF_SIDEFOB_NAME_B    = 0x48;
static constexpr size_t    OFF_SIDEFOB_CAPTION_A = 0x50;
static constexpr size_t    OFF_SIDEFOB_CAPTION_B = 0x58;
static constexpr size_t    OFF_NODE_FLAGS        = 0x90;
static constexpr uint8_t   NODE_FLAG_STENCIL     = 0x2;

static std::unordered_map<void*, float> gRtl;
static std::unordered_map<void*, uint64_t> gRtlTextKey;
static std::mutex gRtlMtx;
static constexpr size_t MAX_RTL_TEXT_KEYS = 4096;

struct RtlReflection
{
    float written;
    float textWidth;
};
static std::unordered_map<void*, RtlReflection> gRtlWritten;

static constexpr size_t OFF_SCROLL_SPEED = 0x1B0;
static constexpr size_t OFF_SCROLL_DELAY = 0x1BC;
static constexpr float  OWN_CLOCK_DELAY  = 1.5f;
static constexpr float  OWN_CLOCK_MAX_DT = 0.1f;

struct OwnScrollClock
{
    LARGE_INTEGER last;
    float waited;
    float textWidth;
};
static std::unordered_map<void*, OwnScrollClock> gOwnClock;
static std::atomic<int> gOwnClockLogBudget{ 4 };
static std::unordered_map<void*, uint64_t> gDriverSeen;
static constexpr uint64_t DRIVER_FRESH_MS = 100;
static std::unordered_map<void*, int> gScrollTraceCount;
static std::atomic<int> gScrollTraceNodes{ 10 };

static void TraceScroll(void* node, const char* who, float delayBefore, float delayAfter, float posBefore,
                        float posAfter, float textWidth, float displayWidth)
{
    if (!RL_DiagnosticsEnabled())
        return;
    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        auto it = gScrollTraceCount.find(node);
        if (it == gScrollTraceCount.end())
        {
            if (gScrollTraceNodes.fetch_sub(1) <= 0)
                return;
            it = gScrollTraceCount.emplace(node, 0).first;
        }
        if (++it->second > 6)
            return;
    }
    LogDetail("[ScrollTrace] %s node=%p t=%llu delay %.3f->%.3f pos %.1f->%.1f T=%.0f W=%.0f\n", who, node,
        static_cast<unsigned long long>(GetTickCount64()), delayBefore, delayAfter, posBefore, posAfter, textWidth,
        displayWidth);
}

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

static void RequestTextRebuild(void* node)
{
    __try { *reinterpret_cast<uint16_t*>(reinterpret_cast<char*>(node) + 0x90) |= 0x10; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static bool SafeCopyCString(const char* src, char* dst, size_t dstSize)
{
    if (!dst || dstSize == 0)
        return false;

    dst[0] = '\0';
    if (!src)
        return false;

    __try
    {
        size_t i = 0;
        for (; i + 1 < dstSize; ++i)
        {
            const char c = src[i];
            if (c == '\0')
                break;
            dst[i] = c;
        }
        dst[i] = '\0';
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        dst[0] = '\0';
        return false;
    }
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

static constexpr size_t MAX_ARABIC_SET_NODES = 8192;
static std::mutex gArabicSetMtx;
static std::unordered_set<void*> gArabicSetNodes;

static void NoteTextSet(void* node, const char* text)
{
    if (!node)
        return;
    const bool arabic = IsArabicSafe() && ContainsArabicSafe(text);
    std::lock_guard<std::mutex> lk(gArabicSetMtx);
    if (!arabic)
    {
        gArabicSetNodes.erase(node);
        return;
    }
    if (gArabicSetNodes.size() > MAX_ARABIC_SET_NODES)
        gArabicSetNodes.clear();
    gArabicSetNodes.insert(node);
}

static bool TextSetAsArabic(void* node)
{
    std::lock_guard<std::mutex> lk(gArabicSetMtx);
    return gArabicSetNodes.count(node) != 0;
}

static void ForgetArabicTextNodes()
{
    std::lock_guard<std::mutex> lk(gArabicSetMtx);
    gArabicSetNodes.clear();
}

static bool NodeFirstText(void* node, char* dst, size_t dstSize)
{
    if (!node || !dst || dstSize == 0)
        return false;

    dst[0] = '\0';

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
        if (text && SafeCopyCString(reinterpret_cast<const char*>(text), dst, dstSize) && dst[0] != '\0')
            return true;
    }

    dst[0] = '\0';
    return false;
}

static std::atomic<int> gScrollDiagBudget{ 200 };
static std::mutex gScrollDiagMtx;
static std::unordered_set<void*> gScrollDiagSeen;

static void DiagScrollNode(void* node, uint8_t state, bool isRtl, bool haveShadow)
{
    if (gScrollDiagBudget.load() <= 0 || !RL_DiagnosticsEnabled())
        return;

    char buf[128] = {};
    if (!NodeFirstText(node, buf, sizeof(buf)))
        return;

    {
        std::lock_guard<std::mutex> lk(gScrollDiagMtx);
        if (!gScrollDiagSeen.insert(node).second)
            return;
    }

    float textW = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, textW);

    const float dispW = gGetDisplayW ? gGetDisplayW(node) : 0.0f;

    gScrollDiagBudget.fetch_sub(1);

    LogDetail("[ScrollDiag] node=%p state=%u rtl=%d shadow=%d arabic=%d textW=%.2f dispW=%.2f text=[%s]\n",
        node, static_cast<unsigned>(state), isRtl ? 1 : 0, haveShadow ? 1 : 0,
        NodeTextIsArabic(node) ? 1 : 0, textW, dispW, buf);
}

static uint64_t TextKeySafe(const char* text)
{
    uint64_t key = 1469598103934665603ull;
    __try
    {
        for (size_t i = 0; text && text[i] && i < 4096; ++i)
        {
            key ^= static_cast<uint8_t>(text[i]);
            key *= 1099511628211ull;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
    return key;
}

static void StampRtlTextLocked(void* node, uint64_t key)
{
    auto stamped = gRtlTextKey.find(node);
    if (stamped != gRtlTextKey.end() && stamped->second == key && gRtl.find(node) != gRtl.end())
        return;
    if (gRtlTextKey.size() >= MAX_RTL_TEXT_KEYS)
        gRtlTextKey.clear();
    gRtl[node] = 0.0f;
    gRtlTextKey[node] = key;
}

static void StampNode(void* node, const char* text)
{
    if (!node)
        return;

    const bool rtl = IsArabicSafe() && ContainsArabicSafe(text);
    const uint64_t key = rtl ? TextKeySafe(text) : 0;

    std::lock_guard<std::mutex> lk(gRtlMtx);
    if (rtl)
        StampRtlTextLocked(node, key);
    else
    {
        gRtl.erase(node);
        gRtlTextKey.erase(node);
    }
}

static void ForgetOwnClock(void* node)
{
    std::lock_guard<std::mutex> lk(gRtlMtx);
    gOwnClock.erase(node);
}

static void MarkNodeMoved(void* node)
{
    __try
    {
        *reinterpret_cast<uint16_t*>(reinterpret_cast<char*>(node) + OFF_NODE_FLAGS) |= 0x10;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static float AdvanceOwnClock(void* node, float s, float textWidth, float displayWidth)
{
    LARGE_INTEGER now{};
    LARGE_INTEGER freq{};
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&freq);
    if (freq.QuadPart <= 0)
        return s;

    float dt = 0.0f;
    bool started = false;
    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        auto it = gOwnClock.find(node);
        if (it == gOwnClock.end() || it->second.textWidth != textWidth)
        {
            gOwnClock[node] = OwnScrollClock{ now, 0.0f, textWidth };
            started = true;
        }
        else
        {
            dt = static_cast<float>(static_cast<double>(now.QuadPart - it->second.last.QuadPart) /
                                    static_cast<double>(freq.QuadPart));
            if (dt < 0.0f)
                dt = 0.0f;
            if (dt > OWN_CLOCK_MAX_DT)
                dt = OWN_CLOCK_MAX_DT;
            it->second.last = now;
            if (it->second.waited < OWN_CLOCK_DELAY)
            {
                it->second.waited += dt;
                return s;
            }
        }
    }

    if (started)
    {
        if (gOwnClockLogBudget.fetch_sub(1) > 0)
            Log("[ArabScroll] the game's scroll clock does not run on this screen - the DLL scrolls the Arabic text "
                "itself (node %p, text %.0f wider than the box %.0f).\n", node, textWidth, displayWidth);
        return s;
    }

    float speed = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_SCROLL_SPEED, speed);
    if (!(speed > 0.0f))
        speed = 80.0f;

    s += dt * speed;
    if (s > textWidth)
        s = -displayWidth;
    MarkNodeMoved(node);
    return s;
}

static constexpr size_t MAX_DRIVER_SEEN = 4096;
static std::atomic<bool> gRtlWasArabic{ false };

static void ReleaseRtlNodeLocked(void* node)
{
    auto wit = gRtlWritten.find(node);
    if (wit != gRtlWritten.end())
    {
        float* pos = reinterpret_cast<float*>(reinterpret_cast<char*>(node) + OFF_SCROLL_POS);
        uint8_t state = 0;
        float current = 0.0f;
        if (SafeReadU8(reinterpret_cast<char*>(node) + OFF_SCROLL_STATE, state) && SafeReadF(pos, current) &&
            current == wit->second.written)
        {
            const auto it = gRtl.find(node);
            SafeWriteF(pos, state == 0 || it == gRtl.end() ? 0.0f : it->second);
        }
        gRtlWritten.erase(wit);
    }
    gRtl.erase(node);
    gRtlTextKey.erase(node);
    gOwnClock.erase(node);
}

static constexpr size_t OFF_NODE_NAME = 0x6C;
static constexpr size_t MAX_MARQUEE_ANCHORS = 512;

struct MarqueeAnchor
{
    uint32_t name;
    uint8_t line;
    uint8_t driver;
};
static std::unordered_map<void*, MarqueeAnchor> gMarqueeAnchor;
static std::atomic<int> gMarqueeAnchorCount{ 0 };
static std::atomic<int> gMarqueeAnchorLogBudget{ 6 };

static void KeepMarqueeAnchorLeft(void* node, bool marquee)
{
    uint8_t line = 0;
    uint8_t driver = 3;
    uint32_t name = 0;
    if (!SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, line) ||
        !SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, driver) ||
        !SafeReadU32(reinterpret_cast<char*>(node) + OFF_NODE_NAME, name))
        return;

    if (marquee)
    {
        const uint8_t anchor = driver == 3 ? line : driver;
        if (anchor == 0)
            return;
        {
            std::lock_guard<std::mutex> lk(gRtlMtx);
            if (gMarqueeAnchor.size() >= MAX_MARQUEE_ANCHORS)
            {
                gMarqueeAnchor.clear();
                gMarqueeAnchorCount.store(0);
            }
            if (gMarqueeAnchor.emplace(node, MarqueeAnchor{ name, line, driver }).second)
                gMarqueeAnchorCount.fetch_add(1);
        }
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, 0);
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, 3);
        MarkNodeMoved(node);
        if (gMarqueeAnchorLogBudget.fetch_sub(1) > 0)
            Log("[ArabScroll] clipped scrolling text %08X was anchored %u - moved its anchor to the left edge so the "
                "clip covers its box (node %p).\n", name, static_cast<unsigned>(anchor), node);
        return;
    }

    if (gMarqueeAnchorCount.load() == 0)
        return;
    MarqueeAnchor original{};
    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        auto it = gMarqueeAnchor.find(node);
        if (it == gMarqueeAnchor.end())
            return;
        original = it->second;
        gMarqueeAnchor.erase(it);
        gMarqueeAnchorCount.fetch_sub(1);
    }
    if (original.name == name && line == 0 && driver == 3)
    {
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, original.line);
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, original.driver);
        MarkNodeMoved(node);
    }
}

static float RtlScrollStart(void* node, float T, float W)
{
    uint8_t align = 0;
    if (gCassetteListDepth.load() > 0 || !SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, align))
        align = 0;
    if (align == ALIGN_RIGHT)
        return 0.0f;
    if (align == 1)
        return (T - W) * 0.5f;
    return T - W;
}

static constexpr size_t MAX_TASK_ROWS = 256;
static constexpr float TASK_ROW_SLACK = 6.0f;
static constexpr float TASK_ROW_DELAY = 1.5f;
static constexpr float TASK_ROW_MAX_DT = 0.1f;
static constexpr float TASK_ROW_SPEED = 80.0f;
static constexpr uint8_t TASK_ROW_SCROLLING = 2;
static constexpr uint8_t ALIGN_FOLLOWS_LINE = 3;

struct TaskRow
{
    uint32_t name;
    float width;
    float scrolled;
    float waited;
    LARGE_INTEGER last;
    bool marquee;
    bool applied;
};
static std::unordered_map<void*, TaskRow> gTaskRows;
static std::atomic<int> gTaskRowCount{ 0 };
static std::atomic<int> gTaskRowLogBudget{ 8 };

static bool IsTaskRow(void* node)
{
    if (gTaskRowCount.load(std::memory_order_relaxed) == 0)
        return false;
    std::lock_guard<std::mutex> lk(gRtlMtx);
    return gTaskRows.find(node) != gTaskRows.end();
}

static bool SetNodeStencil(void* node, bool on)
{
    __try
    {
        uint16_t& flags = *reinterpret_cast<uint16_t*>(reinterpret_cast<char*>(node) + OFF_NODE_FLAGS);
        const bool was = (flags & NODE_FLAG_STENCIL) != 0;
        if (was == on)
            return false;
        flags = static_cast<uint16_t>(on ? flags | NODE_FLAG_STENCIL : flags & ~NODE_FLAG_STENCIL);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool WriteU8IfDifferent(void* address, uint8_t value)
{
    uint8_t current = 0;
    if (SafeReadU8(address, current) && current == value)
        return false;
    SafeWriteU8(address, value);
    return true;
}

static bool WriteFIfDifferent(void* address, float value)
{
    float current = 0.0f;
    if (SafeReadF(address, current) && current == value)
        return false;
    SafeWriteF(address, value);
    return true;
}

static void RegisterTaskRow(void* node)
{
    uint32_t name = 0;
    if (!SafeReadU32(reinterpret_cast<char*>(node) + OFF_NODE_NAME, name))
        return;
    std::lock_guard<std::mutex> lk(gRtlMtx);
    auto it = gTaskRows.find(node);
    if (it != gTaskRows.end() && it->second.name == name)
        return;
    if (gTaskRows.size() >= MAX_TASK_ROWS)
        gTaskRows.clear();
    gTaskRows[node] = TaskRow{ name, -1.0f, 0.0f, 0.0f, LARGE_INTEGER{}, false, false };
    gTaskRowCount.store(static_cast<int>(gTaskRows.size()));
    gRtl.erase(node);
    gRtlTextKey.erase(node);
    gRtlWritten.erase(node);
    gOwnClock.erase(node);
    if (gMarqueeAnchor.erase(node) != 0)
        gMarqueeAnchorCount.fetch_sub(1);
}

static bool ApplyTaskRow(void* node, float* written)
{
    if (!IsTaskRow(node))
        return false;
    char* base = reinterpret_cast<char*>(node);
    uint32_t name = 0;
    if (!SafeReadU32(base + OFF_NODE_NAME, name))
        return false;
    float textWidth = 0.0f;
    SafeReadF(base + OFF_TEXT_WIDTH, textWidth);
    const float displayWidth = gGetDisplayW ? gGetDisplayW(node) : 0.0f;
    float speed = 0.0f;
    SafeReadF(base + OFF_SCROLL_SPEED, speed);
    if (!(speed > 0.0f))
        speed = TASK_ROW_SPEED;
    LARGE_INTEGER now{};
    LARGE_INTEGER freq{};
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&freq);

    bool overflow = false;
    bool turned = false;
    float scrolled = 0.0f;
    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        auto it = gTaskRows.find(node);
        if (it == gTaskRows.end())
            return false;
        if (it->second.name != name)
        {
            gTaskRows.erase(it);
            gTaskRowCount.store(static_cast<int>(gTaskRows.size()));
            return false;
        }
        TaskRow& row = it->second;
        overflow = displayWidth > 0.0f && textWidth > displayWidth + TASK_ROW_SLACK;
        if (!overflow || !row.marquee || row.width != textWidth)
        {
            turned = !row.applied || row.marquee != overflow || row.width != textWidth;
            row.width = textWidth;
            row.scrolled = 0.0f;
            row.waited = 0.0f;
            row.last = now;
            row.marquee = overflow;
            row.applied = true;
        }
        else if (freq.QuadPart > 0)
        {
            float dt = static_cast<float>(static_cast<double>(now.QuadPart - row.last.QuadPart) /
                                          static_cast<double>(freq.QuadPart));
            if (!(dt > 0.0f))
                dt = 0.0f;
            if (dt > TASK_ROW_MAX_DT)
                dt = TASK_ROW_MAX_DT;
            row.last = now;
            if (row.waited < TASK_ROW_DELAY)
            {
                row.waited += dt;
            }
            else
            {
                row.scrolled += dt * speed;
                if (row.scrolled > textWidth)
                    row.scrolled = -displayWidth;
            }
        }
        scrolled = row.scrolled;
    }

    const bool arabic = TextSetAsArabic(node);
    bool changed = false;
    float pos = 0.0f;
    if (overflow)
    {
        pos = arabic ? (textWidth - displayWidth) - scrolled : scrolled;
        changed |= SetNodeStencil(node, true);
        changed |= WriteU8IfDifferent(base + OFF_ALIGN, 0);
        changed |= WriteU8IfDifferent(base + OFF_ALIGN_DRIVER, ALIGN_FOLLOWS_LINE);
        changed |= WriteFIfDifferent(base + OFF_SCROLL_POS, pos);
        SafeWriteU8(base + OFF_SCROLL_STATE, TASK_ROW_SCROLLING);
        SafeWriteF(base + OFF_SCROLL_DELAY, 0.0f);
    }
    else
    {
        changed |= SetNodeStencil(node, false);
        changed |= WriteU8IfDifferent(base + OFF_ALIGN, ALIGN_RIGHT);
        changed |= WriteU8IfDifferent(base + OFF_ALIGN_DRIVER, ALIGN_RIGHT);
        changed |= WriteFIfDifferent(base + OFF_SCROLL_POS, 0.0f);
        SafeWriteU8(base + OFF_SCROLL_STATE, 0);
    }
    if (changed)
        MarkNodeMoved(node);
    if (written)
        *written = pos;
    if (turned && textWidth > 0.0f && gTaskRowLogBudget.load() > 0 && gTaskRowLogBudget.fetch_sub(1) > 0)
        Log("[ArabScroll] objective row %08X (node %p): text %.0f wide in a %.0f box - %s.\n", name, node, textWidth,
            displayWidth,
            overflow ? "clipped to its box and scrolled by the DLL" : "fits, shown right-aligned with the clip off");
    return true;
}

static void __fastcall hkScrollDriver(void* node, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7)
{

    if (!node)
    {
        oScrollDriver(node, a2, a3, a4, a5, a6, a7);
        return;
    }

    if (!IsArabicSafe())
    {
        KeepMarqueeAnchorLeft(node, false);
        {
            std::lock_guard<std::mutex> lk(gRtlMtx);
            ReleaseRtlNodeLocked(node);
            if (gRtlWasArabic.exchange(false))
            {
                gRtl.clear();
                gRtlTextKey.clear();
                gOwnClock.clear();
                gDriverSeen.clear();
                gTaskRows.clear();
                gTaskRowCount.store(0);
                ForgetArabicTextNodes();
            }
        }
        oScrollDriver(node, a2, a3, a4, a5, a6, a7);
        return;
    }
    gRtlWasArabic.store(true);

    float rowPos = 0.0f;
    if (gTaskRowCount.load(std::memory_order_relaxed) != 0 && ApplyTaskRow(node, &rowPos))
    {
        oScrollDriver(node, a2, a3, a4, a5, a6, a7);
        if (WriteFIfDifferent(reinterpret_cast<char*>(node) + OFF_SCROLL_POS, rowPos))
            MarkNodeMoved(node);
        return;
    }

    uint8_t state = 0;
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_SCROLL_STATE, state);

    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        if (gDriverSeen.size() > MAX_DRIVER_SEEN)
            gDriverSeen.clear();
        gDriverSeen[node] = GetTickCount64();
    }

    const bool cassetteActive = (gCassetteListDepth.load() > 0) && IsArabicSafe();

    float* pos = reinterpret_cast<float*>(reinterpret_cast<char*>(node) + OFF_SCROLL_POS);
    float textNow = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, textNow);
    const float displayNow = gGetDisplayW ? gGetDisplayW(node) : 0.0f;
    const bool overflowsNow = displayNow > 0.0f && textNow > displayNow;

    if (!cassetteActive)
    {
        uint8_t nodeFlags = 0;
        SafeReadU8(reinterpret_cast<char*>(node) + OFF_NODE_FLAGS, nodeFlags);
        KeepMarqueeAnchorLeft(node, (nodeFlags & NODE_FLAG_STENCIL) != 0 && overflowsNow);
    }

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
        auto wit = gRtlWritten.find(node);
        if (wit != gRtlWritten.end() && textNow > 0.0f && (!overflowsNow || wit->second.textWidth != textNow))
        {
            float current = 0.0f;
            if (SafeReadF(pos, current) && current == wit->second.written)
                SafeWriteF(pos, state == 0 ? 0.0f : shadow);
            gRtlWritten.erase(wit);
            haveShadow = false;
        }
    }

    if (!isRtl && state != 0 && IsArabicSafe() &&
        (cassetteActive || TextSetAsArabic(node) || NodeTextIsArabic(node)))
        isRtl = true;

    if (state != 0 && IsArabicSafe())
        DiagScrollNode(node, state, isRtl, haveShadow);

    if (!isRtl && !cassetteActive)
    {
        oScrollDriver(node, a2, a3, a4, a5, a6, a7);
        return;
    }

    const bool fed = isRtl && state == 2 && haveShadow && overflowsNow;
    if (fed)
        SafeWriteF(pos, shadow);

    float delayBefore = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_SCROLL_DELAY, delayBefore);

    oScrollDriver(node, a2, a3, a4, a5, a6, a7);

    if (cassetteActive)
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, ALIGN_RIGHT);

    if (!isRtl)
        return;

    float s = 0.0f;
    SafeReadF(pos, s);

    float delayAfter = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_SCROLL_DELAY, delayAfter);
    const bool stalledWait = state == 1 && overflowsNow && delayAfter == delayBefore;
    if (state == 2 && overflowsNow)
        TraceScroll(node, fed ? "driver" : "driver-unfed", delayBefore, delayAfter, shadow, s, textNow, displayNow);
    else if (stalledWait)
        TraceScroll(node, "waiting-frozen", delayBefore, delayAfter, shadow, s, textNow, displayNow);
    float speed = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_SCROLL_SPEED, speed);
    if (!(speed > 0.0f))
        speed = 80.0f;
    const float maxStep = speed * 0.25f;
    const bool frozen = s == shadow && delayAfter == delayBefore;
    const bool normalWrap = s < 0.0f && shadow + maxStep >= textNow;
    const bool jumped = (s - shadow > maxStep || shadow - s > maxStep) && !normalWrap;
    if ((fed && (frozen || jumped)) || stalledWait)
        s = AdvanceOwnClock(node, shadow, textNow, displayNow);
    else
        ForgetOwnClock(node);

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
    {
        const float reflected = RtlScrollStart(node, T, W) - s;
        SafeWriteF(pos, reflected);
        std::lock_guard<std::mutex> lk(gRtlMtx);
        gRtlWritten[node] = RtlReflection{ reflected, T };
    }
    else if (W > 0.0f && T > 0.0f && state != 0 && s != 0.0f)
    {
        SafeWriteF(pos, 0.0f);
        std::lock_guard<std::mutex> lk(gRtlMtx);
        gRtl[node] = 0.0f;
        gRtlWritten.erase(node);
    }
}

void DriveStalledArabicScroll(void* node)
{
    if (!node || !IsArabicSafe() || IsTaskRow(node))
        return;

    uint8_t state = 0;
    if (!SafeReadU8(reinterpret_cast<char*>(node) + OFF_SCROLL_STATE, state) || state != 2)
        return;

    float T = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, T);
    const float W = gGetDisplayW ? gGetDisplayW(node) : 0.0f;
    if (!(W > 0.0f && T > W))
        return;

    float s = 0.0f;
    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        auto seen = gDriverSeen.find(node);
        if (seen != gDriverSeen.end() && GetTickCount64() - seen->second < DRIVER_FRESH_MS)
            return;
        auto it = gRtl.find(node);
        if (it == gRtl.end())
            return;
        s = it->second;
    }

    const float next = AdvanceOwnClock(node, s, T, W);
    TraceScroll(node, "draw-own-clock", 0.0f, 0.0f, s, next, T, W);
    const float reflected = RtlScrollStart(node, T, W) - next;
    SafeWriteF(reinterpret_cast<char*>(node) + OFF_SCROLL_POS, reflected);
    std::lock_guard<std::mutex> lk(gRtlMtx);
    gRtl[node] = next;
    gRtlWritten[node] = RtlReflection{ reflected, T };
}

bool ArabicMarqueeOverflowing(void* node)
{
    if (!node || !gGetDisplayW)
        return false;
    uint8_t flags = 0;
    if (!SafeReadU8(reinterpret_cast<char*>(node) + OFF_NODE_FLAGS, flags) || !(flags & NODE_FLAG_STENCIL))
        return false;
    float T = 0.0f;
    if (!SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, T))
        return false;
    const float W = gGetDisplayW(node);
    return W > 0.0f && T > W;
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
    if (!IsArabicSafe())
    {
        std::lock_guard<std::mutex> lk(gRtlMtx);
        ReleaseRtlNodeLocked(node);
        return;
    }
    if (!ContainsArabicSafe(text))
        return;

    const uint64_t key = TextKeySafe(text);
    std::lock_guard<std::mutex> lk(gRtlMtx);
    StampRtlTextLocked(node, key);
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

    if (!thisPtr)
        return;

    void* node = nullptr;
    if (!IsArabicSafe())
    {
        if (SafeReadPtr(reinterpret_cast<char*>(thisPtr) + 0x10, node) && node)
        {
            std::lock_guard<std::mutex> lk(gRtlMtx);
            ReleaseRtlNodeLocked(node);
        }
        return;
    }

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

struct EquipOriginalAlign
{
    uint8_t line;
    uint8_t block;
};

static std::mutex gEquipClassMtx;
static std::unordered_map<void*, int> gEquipClass;
static std::unordered_map<void*, EquipOriginalAlign> gEquipOrigAlign;

static void RememberOriginalAlign(void* node, uint8_t line, uint8_t block)
{
    std::lock_guard<std::mutex> lk(gEquipClassMtx);
    if (gEquipOrigAlign.find(node) == gEquipOrigAlign.end())
        gEquipOrigAlign[node] = { line, block };
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
    EquipOriginalAlign orig{};
    {
        std::lock_guard<std::mutex> lk(gEquipClassMtx);
        auto it = gEquipOrigAlign.find(node);
        if (it == gEquipOrigAlign.end())
            return;
        orig = it->second;
    }

    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, orig.line);
    SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, orig.block);

    std::lock_guard<std::mutex> lk(gRtlMtx);
    gRtl.erase(node);
    gRtlTextKey.erase(node);
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

        LogDetail("[TitleDiag] node=%p caller_va=0x%llx text=%s\n",
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

using TrackRecordStart_t = void(__fastcall*)(void* record, void* owner);
static TrackRecordStart_t oTrackRecordStart = nullptr;
static uintptr_t* gTrackRecordStartVtSlot = nullptr;

static void __fastcall hkTrackRecordStart(void* record, void* owner)
{
    oTrackRecordStart(record, owner);
    ForceRowNameRightAlign(record);
}

static constexpr size_t OFF_STAFF_ROW_NAME_NODE = 0x88;

static void __fastcall hkStaffRowName(void* record, void* staff, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                                      uint64_t a7)
{
    oStaffRowName(record, staff, a3, a4, a5, a6, a7);

    if (!record || !IsArabicSafe())
        return;

    void* node = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(record) + OFF_STAFF_ROW_NAME_NODE, node) && node && NodeTextIsArabic(node))
        ForceNodeRightAlignIfFits(node);
}

static constexpr size_t OFF_SECTION_INFO_NODE = 0x5D48;

static uint64_t __fastcall hkSectionInfoText(void* self, void* record)
{
    const uint64_t result = oSectionInfoText(self, record);

    if (!self || !IsArabicSafe())
        return result;

    void* node = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + OFF_SECTION_INFO_NODE, node) && node && NodeTextIsArabic(node))
        ForceNodeRightAlignIfFits(node);
    return result;
}

static constexpr size_t OFF_STAFF_DETAILS_NAME_NODE = 0x68D8;

static void __fastcall hkStaffDetails(void* self)
{
    oStaffDetails(self);

    if (!self || !IsArabicSafe())
        return;

    void* node = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + OFF_STAFF_DETAILS_NAME_NODE, node) && node && NodeTextIsArabic(node))
        ForceNodeRightAlignIfFits(node);
}

static constexpr size_t OFF_BASE_FACILITY_UIX = 0x28;
static constexpr size_t OFF_BASE_FACILITY_MODELS = 0x40;
static constexpr size_t OFF_BASE_FACILITY_LAYOUTS = 0x1358;
static constexpr uint64_t BASE_FACILITY_LAYOUT_HASH = 0x4715E150D64Dull;
static constexpr uint64_t BASE_FACILITY_MODEL_INDEX = 4;
static constexpr uint64_t BASE_FACILITY_INFO_PARENT_HASH = 0x43EC68E337DAull;
static constexpr uint64_t BASE_FACILITY_INFO_TEXT_HASH = 0xE65790C5E5ADull;

static uintptr_t VirtualAt(void* obj, size_t slotOffset)
{
    return *reinterpret_cast<uintptr_t*>(*reinterpret_cast<uintptr_t*>(obj) + slotOffset);
}

static void* FindBaseFacilityInfoNode(void* self)
{
    __try
    {
        auto* base = reinterpret_cast<char*>(self);
        void* uix = *reinterpret_cast<void**>(base + OFF_BASE_FACILITY_UIX);
        void* models = *reinterpret_cast<void**>(base + OFF_BASE_FACILITY_MODELS);
        void* layouts = *reinterpret_cast<void**>(base + OFF_BASE_FACILITY_LAYOUTS);
        if (!uix || !models || !layouts)
            return nullptr;

        const uint64_t layout = reinterpret_cast<LookupByHash_t>(VirtualAt(layouts, 0xA8))(layouts, BASE_FACILITY_LAYOUT_HASH);
        const uint64_t model = reinterpret_cast<LookupModel_t>(VirtualAt(models, 0xC8))(models, BASE_FACILITY_MODEL_INDEX, layout);
        const uint64_t parent =
            reinterpret_cast<LookupChild_t>(VirtualAt(uix, 0x248))(uix, model, BASE_FACILITY_INFO_PARENT_HASH);
        if (!parent)
            return nullptr;
        return reinterpret_cast<void*>(
            reinterpret_cast<LookupChild_t>(VirtualAt(uix, 0x280))(uix, parent, BASE_FACILITY_INFO_TEXT_HASH));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
}

static void __fastcall hkBaseFacilityInfo(void* self)
{
    oBaseFacilityInfo(self);

    if (!self || !IsArabicSafe())
        return;

    void* node = FindBaseFacilityInfoNode(self);
    if (node && NodeTextIsArabic(node))
        ForceNodeRightAlignIfFits(node);
}

static constexpr size_t OFF_RESOURCE_INFO_NODE = 0x8F0;

static void __fastcall hkResourceInfo(void* self)
{
    oResourceInfo(self);

    if (!self || !IsArabicSafe())
        return;

    void* node = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + OFF_RESOURCE_INFO_NODE, node) && node && NodeTextIsArabic(node))
        ForceNodeRightAlignIfFits(node);
}

static constexpr size_t OFF_ANNOUNCE_POPUP_TITLE_NODE = 0x40;
static constexpr size_t OFF_ANNOUNCE_POPUP_BODY_NODE = 0x48;

static constexpr uint32_t ANNOUNCE_BODY_LEASE_MS = 300;

static std::atomic<int> gAnnounceDiagBudget{ 4 };
static std::atomic<int> gAnnounceBodyLogBudget{ 6 };
static std::atomic<void*> gArabicAnnounceBody{ nullptr };
static std::atomic<int> gWideBoxLogBudget{ 8 };
static std::atomic<uint32_t> gLastWideBoxWidth{ 0 };

static std::atomic<int> gEventPopupTextLogBudget{ 8 };
static std::atomic<uint64_t> gLastEventPopupTextHash{ 0 };

static void NoteEventPopupText(void* node)
{
    if (gEventPopupTextLogBudget.load() <= 0)
        return;
    char text[96] = {};
    if (!NodeFirstText(node, text, sizeof(text)))
        return;
    uint64_t hash = 1469598103934665603ull;
    for (const char* p = text; *p; ++p)
        hash = (hash ^ static_cast<uint8_t>(*p)) * 1099511628211ull;
    if (gLastEventPopupTextHash.exchange(hash) == hash)
        return;
    gEventPopupTextLogBudget.fetch_sub(1);
    uint8_t d8 = 0;
    uint8_t da = 0;
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, d8);
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, da);
    Log("[ArabScroll] event popup body now d8=%u da=%u: %s\n", static_cast<unsigned>(d8), static_cast<unsigned>(da), text);
}

static void NoteWideBoxText(const char* role, void* node)
{
    float T = 0.0f;
    if (!SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, T))
        return;
    const float W = gGetDisplayW ? gGetDisplayW(node) : 0.0f;
    if (!(W > 0.0f) || !(T > W) || gWideBoxLogBudget.load() <= 0)
        return;
    uint32_t bits = 0;
    std::memcpy(&bits, &T, sizeof(bits));
    if (gLastWideBoxWidth.exchange(bits) == bits)
        return;
    gWideBoxLogBudget.fetch_sub(1);
    Log("[ArabScroll] %s is wider than its box (%.1f > %.1f) - right-aligned anyway, box text does not scroll\n", role, T,
        W);
}

static void NoteAnnounceNode(const char* role, void* node, bool arabic)
{
    if (!RL_DiagnosticsEnabled())
        return;
    uint8_t d8 = 0xFF;
    uint8_t da = 0xFF;
    float T = 0.0f;
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, d8);
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, da);
    SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, T);
    const float W = gGetDisplayW ? gGetDisplayW(node) : -1.0f;
    LogDetail("[AnnouncePopupDiag] %s node=%p arabic=%d after: d8=%u da=%u textW=%.1f dispW=%.1f\n", role, node,
        arabic ? 1 : 0, static_cast<unsigned>(d8), static_cast<unsigned>(da), T, W);
}

static bool AnnounceBodyIsArabic(void* body, uint32_t builtBefore, uint32_t arabicBuiltBefore, bool& rebuilt)
{
    uint32_t built = 0;
    uint32_t arabicBuilt = 0;
    CountTextUnitBuildsOnThisThread(built, arabicBuilt);
    rebuilt = built != builtBefore;
    if (arabicBuilt != arabicBuiltBefore)
        gArabicAnnounceBody.store(body);
    else if (rebuilt && gArabicAnnounceBody.load() == body)
        gArabicAnnounceBody.store(nullptr);
    return gArabicAnnounceBody.load() == body || NodeTextIsArabic(body);
}

static void __fastcall hkAnnouncePopupStart(void* self, void* owner)
{
    uint32_t builtBefore = 0;
    uint32_t arabicBuiltBefore = 0;
    CountTextUnitBuildsOnThisThread(builtBefore, arabicBuiltBefore);

    oAnnouncePopupStart(self, owner);

    if (!self || !IsArabicSafe())
        return;

    const bool diag = gAnnounceDiagBudget.load() > 0 && gAnnounceDiagBudget.fetch_sub(1) > 0;

    void* title = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + OFF_ANNOUNCE_POPUP_TITLE_NODE, title) && title)
    {
        ForceNodeRightAlignIfFits(title);
        if (diag)
            NoteAnnounceNode("title", title, NodeTextIsArabic(title));
    }

    void* body = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + OFF_ANNOUNCE_POPUP_BODY_NODE, body) && body)
    {
        bool rebuilt = false;
        const bool arabic = AnnounceBodyIsArabic(body, builtBefore, arabicBuiltBefore, rebuilt);
        if (arabic)
        {
            ForceNodeRightAlignAlways(body);
            KeepArabicLinesRightAlignedWhileShown(body, ANNOUNCE_BODY_LEASE_MS);
        }
        NoteWideBoxText("announcement popup body", body);
        if (diag || (rebuilt && gAnnounceBodyLogBudget.load() > 0 && gAnnounceBodyLogBudget.fetch_sub(1) > 0))
            NoteAnnounceNode("body", body, arabic);
    }
}

static bool SwapPointer(uintptr_t* slot, uintptr_t value)
{
    DWORD oldProtect = 0;
    if (!slot || !VirtualProtect(slot, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect))
        return false;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(slot), static_cast<LONG64>(value));
    DWORD ignored = 0;
    VirtualProtect(slot, sizeof(uintptr_t), oldProtect, &ignored);
    return true;
}

static constexpr size_t OFF_EVENT_POPUP_BODY_NODE = 0x168;
static constexpr size_t OFF_EVENT_POPUP_BUTTON_A = 0x3D8;
static constexpr size_t OFF_EVENT_POPUP_BUTTON_B = 0x400;
static constexpr int MAX_EVENT_POPUP_CAPTURES = 4;

static thread_local void* tEventPopupOwner = nullptr;
static thread_local void* tEventPopupCaptured[MAX_EVENT_POPUP_CAPTURES] = {};
static thread_local int tEventPopupCapturedCount = 0;

static std::atomic<int> gQuestionTraceBudget{ 8 };

static bool TextHasArabicQuestionMark(const char* text)
{
    __try
    {
        for (const char* p = text; p && *p; ++p)
        {
            if (static_cast<uint8_t>(p[0]) == 0xD8 && static_cast<uint8_t>(p[1]) == 0x9F)
                return true;
        }
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void NoteQuestionTextNode(void* node, const char* text)
{
    void* frames[20] = {};
    const USHORT n = RtlCaptureStackBackTrace(2, 20, frames, nullptr);
    const uintptr_t lo = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const uintptr_t hi = lo + 0xA01D000;
    char chain[256] = {};
    size_t used = 0;
    int kept = 0;
    for (USHORT i = 0; i < n && kept < 7; ++i)
    {
        const uintptr_t a = reinterpret_cast<uintptr_t>(frames[i]);
        if (a < lo || a >= hi)
            continue;
        used += static_cast<size_t>(_snprintf_s(chain + used, sizeof(chain) - used, _TRUNCATE, " %llX",
                                                static_cast<unsigned long long>(a - lo + 0x140000000ull)));
        ++kept;
    }
    char sample[80] = {};
    SafeCopyCString(text, sample, sizeof(sample));
    LogDetail("[QuestionTrace] node=%p set from:%s text: %s\n", node, chain, sample);
}

static constexpr uint32_t kCountLimitNodes[] = {
    0xBB6850B8, 0xE6D35EC5, 0x10CEE7D0, 0xC553C8CB, 0x9032951E, 0x7D9DD8D9,
    0x63A5174B, 0xF21EE8CF, 0x1153755A, 0x9C868B05, 0x3E297354, 0xC5F07525,
    0x8D11B65B, 0xA845C7EA, 0xBEB2DC7C, 0xFF018390, 0xC2A2731B, 0x548F0DBD, 0xF9198FE9,
    0x66D3DECD, 0x636E2106, 0x45836778,
};
static constexpr uint32_t kCountLimitDigitNodes[] = {
    0x021A32E0, 0xF3F81BA8,
};
static constexpr size_t COUNT_LIMIT_TEXT_SIZE = 32;
static constexpr size_t COUNT_LIMIT_STORE_CAP = 16384;
static std::mutex gCountLimitMtx;
static std::unordered_set<std::string> gCountLimitStore;
static std::atomic<int> gCountLimitLogBudget{ 3 };

static const char* KeepCountLimitText(const char* text)
{
    std::lock_guard<std::mutex> lk(gCountLimitMtx);
    auto found = gCountLimitStore.find(text);
    if (found != gCountLimitStore.end())
        return found->c_str();
    if (gCountLimitStore.size() >= COUNT_LIMIT_STORE_CAP)
        return nullptr;
    return gCountLimitStore.insert(text).first->c_str();
}

static bool IsDigitField(const char* from, const char* to)
{
    bool digit = false;
    for (const char* p = from; p < to; ++p)
    {
        if (*p >= '0' && *p <= '9')
            digit = true;
        else if (*p != ' ')
            return false;
    }
    return digit;
}

static const char* CountLimitFirst(void* node, const char* text)
{
    uint32_t name = 0;
    if (!node || !text || !SafeReadU32(reinterpret_cast<char*>(node) + OFF_NODE_NAME, name))
        return nullptr;
    size_t row = 0;
    while (row < _countof(kCountLimitNodes) && kCountLimitNodes[row] != name)
        ++row;
    size_t digitRow = 0;
    while (digitRow < _countof(kCountLimitDigitNodes) && kCountLimitDigitNodes[digitRow] != name)
        ++digitRow;
    const bool digitsOnly = digitRow < _countof(kCountLimitDigitNodes);
    if ((row == _countof(kCountLimitNodes) && !digitsOnly) || !IsArabicSafe())
        return nullptr;

    char source[COUNT_LIMIT_TEXT_SIZE] = {};
    if (!SafeCopyCString(text, source, sizeof(source)) || std::strlen(source) + 1 >= sizeof(source))
        return nullptr;
    const char* slash = std::strchr(source, '/');
    if (!slash || slash == source || std::strchr(slash + 1, '/'))
        return nullptr;
    if (digitsOnly && (!IsDigitField(source, slash) || !IsDigitField(slash + 1, source + std::strlen(source))))
        return nullptr;
    const char* limit = slash + 1;
    while (*limit == ' ')
        ++limit;
    const size_t padding = static_cast<size_t>(limit - slash) - 1;
    const size_t limitLength = std::strlen(limit);
    const size_t countLength = static_cast<size_t>(slash - source);
    if (limitLength == 0)
        return nullptr;

    char out[COUNT_LIMIT_TEXT_SIZE] = {};
    std::memset(out, ' ', padding);
    std::memcpy(out + padding, limit, limitLength);
    out[padding + limitLength] = '/';
    std::memcpy(out + padding + limitLength + 1, source, countLength);
    out[padding + limitLength + 1 + countLength] = '\0';
    const char* kept = KeepCountLimitText(out);
    if (kept && gCountLimitLogBudget.load() > 0 && gCountLimitLogBudget.fetch_sub(1) > 0)
        Log("[ArabScroll] count %s shown as %s (node %08X).\n", source, kept, name);
    return kept;
}

static constexpr uint32_t FULTON_COUNT_NODE = 0x6855F14E;
static constexpr uint64_t LANG_CMMN_EMPTY = 0xF358A5E06142ull;
static std::atomic<int> gFultonEmptyLogBudget{ 1 };

static const char* FultonEmptyFullWord(void* node, const char* text)
{
    uint32_t name = 0;
    if (!node || !text || !SafeReadU32(reinterpret_cast<char*>(node) + OFF_NODE_NAME, name) ||
        name != FULTON_COUNT_NODE)
        return nullptr;
    uint8_t first = 0;
    if (!SafeReadU8(text, first) || first == 0 || first == 'x' || !IsArabicSafe())
        return nullptr;
    const char* word = RL_LangText(LANG_CMMN_EMPTY);
    if (word && gFultonEmptyLogBudget.load() > 0 && gFultonEmptyLogBudget.fetch_sub(1) > 0)
        Log("[ArabScroll] fulton count is zero: full word shown instead of the game's 6-byte copy.\n");
    return word;
}

static uint64_t __fastcall hkUixSetTextImpl(void* node, void* unit, const char* text, uint64_t a4, uint64_t a5)
{
    if (const char* label = ArabicRadioFileLabel(text))
        text = label;
    else if (const char* full = FullArabicLabelForShortenedBuffer(text))
        text = full;
    else if (const char* swapped = CountLimitFirst(node, text))
        text = swapped;
    else if (const char* word = FultonEmptyFullWord(node, text))
        text = word;
    NoteTextSet(node, text);

    if (gQuestionTraceBudget.load() > 0 && RL_DiagnosticsEnabled() && text && TextHasArabicQuestionMark(text) &&
        IsArabicSafe() && gQuestionTraceBudget.fetch_sub(1) > 0)
        NoteQuestionTextNode(node, text);

    if (tEventPopupOwner && node && tEventPopupCapturedCount < MAX_EVENT_POPUP_CAPTURES)
    {
        auto* owner = reinterpret_cast<char*>(tEventPopupOwner);
        void* body = nullptr;
        void* buttonA = nullptr;
        void* buttonB = nullptr;
        SafeReadPtr(owner + OFF_EVENT_POPUP_BODY_NODE, body);
        SafeReadPtr(owner + OFF_EVENT_POPUP_BUTTON_A, buttonA);
        SafeReadPtr(owner + OFF_EVENT_POPUP_BUTTON_B, buttonB);
        if (node != body && node != buttonA && node != buttonB)
            tEventPopupCaptured[tEventPopupCapturedCount++] = node;
    }
    return oUixSetTextImpl(node, unit, text, a4, a5);
}

static constexpr size_t OFF_PREFAB_TEXT_NODE = 0x38;
static constexpr size_t OFF_PREFAB_TEXT_MODE = 0x44;
static constexpr size_t MAX_AUTHORED_BLOCK_ALIGNS = 512;

static std::mutex gAuthoredBlockAlignMtx;
static std::unordered_map<void*, uint8_t> gAuthoredBlockAlign;
static std::atomic<int> gPrefabMirrorLogBudget{ 6 };

static constexpr uint32_t UNIT_FLAG_LINE_START = 0x4;

static bool EveryLineStartIsFlagged(void* node, bool logUnits)
{
    void* units = nullptr;
    uint32_t count = 0;
    if (!SafeReadPtr(reinterpret_cast<char*>(node) + OFF_UNIT_ARRAY, units) || !units ||
        !SafeReadU32(reinterpret_cast<char*>(node) + OFF_UNIT_COUNT, count) || count == 0)
        return false;
    if (count > 64)
        count = 64;

    bool ok = true;
    uint16_t previousLine = 0;
    bool pendingEmptyStart = false;
    for (uint32_t i = 0; i < count; ++i)
    {
        auto* unit = reinterpret_cast<char*>(units) + static_cast<size_t>(i) * UNIT_STRIDE;
        uint32_t flags = 0;
        uint32_t packed = 0;
        SafeReadU32(unit + 0x0C, flags);
        SafeReadU32(unit + 0x10, packed);
        const uint16_t chars = static_cast<uint16_t>(packed & 0xFFFF);
        const uint16_t line = static_cast<uint16_t>(packed >> 16);
        if (i > 0 && line != previousLine && (flags & UNIT_FLAG_LINE_START) == 0)
            ok = false;
        if (pendingEmptyStart && line == previousLine && chars > 0 && (flags & UNIT_FLAG_LINE_START) == 0)
            ok = false;
        if (flags & UNIT_FLAG_LINE_START)
            pendingEmptyStart = chars == 0;
        else if (chars > 0)
            pendingEmptyStart = false;
        previousLine = line;
        if (logUnits)
            Log("[ArabScroll]   unit %u: flags=%08X line=%u chars=%u\n", i, flags, static_cast<unsigned>(line),
                static_cast<unsigned>(chars));
    }
    return ok;
}

static void MirrorBoxTextAlignment(void* node)
{
    uint8_t current = 0;
    if (!SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, current))
        return;

    uint8_t authored = current;
    bool firstSight = false;
    {
        std::lock_guard<std::mutex> lk(gAuthoredBlockAlignMtx);
        const auto it = gAuthoredBlockAlign.find(node);
        if (it == gAuthoredBlockAlign.end())
        {
            if (gAuthoredBlockAlign.size() >= MAX_AUTHORED_BLOCK_ALIGNS)
                gAuthoredBlockAlign.clear();
            gAuthoredBlockAlign.emplace(node, current);
            firstSight = true;
        }
        else
        {
            authored = it->second;
        }
    }

    if (authored != current)
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, authored);

    const bool logUnits = firstSight && gPrefabMirrorLogBudget.load() > 0;
    const bool safe = EveryLineStartIsFlagged(node, false);
    if (safe)
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, ALIGN_RIGHT);
    else if (logUnits)
    {
        Log("[ArabScroll] prefab box text %p left as authored: a new line starts without the line-start flag\n", node);
        EveryLineStartIsFlagged(node, true);
    }

    if (firstSight && gPrefabMirrorLogBudget.load() > 0)
    {
        gPrefabMirrorLogBudget.fetch_sub(1);
        uint32_t lines = 0;
        void* widths = nullptr;
        float w0 = 0.0f;
        float w1 = 0.0f;
        float T = 0.0f;
        float transX = 0.0f;
        float boxW = 0.0f;
        auto* p = reinterpret_cast<char*>(node);
        SafeReadU32(p + 0x158, lines);
        SafeReadPtr(p + 0x160, widths);
        if (widths && lines > 0)
            SafeReadF(widths, w0);
        if (widths && lines > 1)
            SafeReadF(reinterpret_cast<char*>(widths) + 4, w1);
        SafeReadF(p + OFF_TEXT_WIDTH, T);
        SafeReadF(p + 0x20, transX);
        SafeReadF(p + 0x40, boxW);
        const float W = gGetDisplayW ? gGetDisplayW(node) : -1.0f;
        Log("[ArabScroll] prefab box text %p: authored block align %u, lines right=%d; lines=%u w0=%.1f w1=%.1f maxW=%.1f "
            "dispW=%.1f transX=%.2f box=%.1f\n",
            node, static_cast<unsigned>(authored), safe ? 1 : 0, lines, w0, w1, T, W, transX, boxW);
        if (safe)
            EveryLineStartIsFlagged(node, true);
    }
}

static void __fastcall hkPrefabTextCallFunc(void* self, void* owner)
{
    oPrefabTextCallFunc(self, owner);

    if (!self || !IsArabicSafe())
        return;

    uint32_t mode = 0;
    void* node = nullptr;
    if (!SafeReadU32(reinterpret_cast<char*>(self) + OFF_PREFAB_TEXT_MODE, mode) || mode < 2 ||
        !SafeReadPtr(reinterpret_cast<char*>(self) + OFF_PREFAB_TEXT_NODE, node) || !node || !NodeTextIsArabic(node))
        return;

    MirrorBoxTextAlignment(node);
}

static void __fastcall hkUpdatePopup(void* self)
{
    const bool arabic = self && IsArabicSafe();
    if (arabic)
    {
        tEventPopupOwner = self;
        tEventPopupCapturedCount = 0;
    }
    oUpdatePopup(self);
    tEventPopupOwner = nullptr;

    if (!arabic)
        return;

    const bool diag = gAnnounceDiagBudget.load() > 0 && gAnnounceDiagBudget.fetch_sub(1) > 0;

    for (int i = 0; i < tEventPopupCapturedCount; ++i)
    {
        ForceNodeRightAlignIfFits(tEventPopupCaptured[i]);
        if (diag)
            NoteAnnounceNode("event title", tEventPopupCaptured[i], NodeTextIsArabic(tEventPopupCaptured[i]));
    }
    tEventPopupCapturedCount = 0;

    void* body = nullptr;
    if (SafeReadPtr(reinterpret_cast<char*>(self) + OFF_EVENT_POPUP_BODY_NODE, body) && body)
    {
        const bool bodyArabic = NodeTextIsArabic(body);
        if (bodyArabic)
            SafeWriteU8(reinterpret_cast<char*>(body) + OFF_ALIGN, ALIGN_RIGHT);
        NoteEventPopupText(body);
        if (diag)
            NoteAnnounceNode("event body", body, bodyArabic);
    }
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
    if (!SafeReadPtr(reinterpret_cast<char*>(self) + OFF_TASK_NODE, node) || !node)
        return;

    RegisterTaskRow(node);
    ApplyTaskRow(node, nullptr);
}

static constexpr size_t OFF_AMMOBOX_TEXT = 0x62;
static constexpr size_t OFF_AMMOBOX_NODE = 0x1D0;
static constexpr size_t OFF_AMMOBOX_UIHOST = 0x48;
static constexpr size_t OFF_AMMOBOX_PARAM3 = 0x40;

using AmmoFmt_t = int(__fastcall*)(void* obj, char* dst, size_t size, const char* fmt,
                                   void* a5, void* a6, void* a7, void* a8,
                                   void* a9, void* a10, void* a11, void* a12, void* a13, void* a14,
                                   void* a15, void* a16, void* a17, void* a18, void* a19, void* a20,
                                   void* a21, void* a22, void* a23, void* a24, void* a25, void* a26,
                                   void* a27, void* a28);
using AmmoBoxText_t = void(__fastcall*)(void* uiObj, void* node, void* p3, uint32_t n,
                                        const char* text, uint8_t f6, uint8_t f7);

static AmmoFmt_t oAmmoFmt = nullptr;
static void* gTargetAmmoFmt = nullptr;
static std::atomic<int> gAmmoFmtHookState{ 0 };

static thread_local bool  gInAmmoBoxInfo = false;
static thread_local bool  gAmmoFullReady = false;
static thread_local char  gAmmoFull[320];

static bool FormatIsTwoLinePair(const char* fmt)
{
    __try
    {
        static const char kPat[] = "%s:%s\n%s:%s";
        for (int i = 0; i < static_cast<int>(sizeof(kPat)); ++i)
            if (fmt[i] != kPat[i])
                return false;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static int __fastcall hkAmmoFmt(void* obj, char* dst, size_t size, const char* fmt,
                                void* a5, void* a6, void* a7, void* a8,
                                void* a9, void* a10, void* a11, void* a12, void* a13, void* a14,
                                void* a15, void* a16, void* a17, void* a18, void* a19, void* a20,
                                void* a21, void* a22, void* a23, void* a24, void* a25, void* a26,
                                void* a27, void* a28)
{
    if (gInAmmoBoxInfo && fmt && FormatIsTwoLinePair(fmt))
    {
        char s1[80] = {}, s2[80] = {}, s3[80] = {}, s4[80] = {};
        SafeCopyCString(reinterpret_cast<const char*>(a5), s1, sizeof(s1));
        SafeCopyCString(reinterpret_cast<const char*>(a6), s2, sizeof(s2));
        SafeCopyCString(reinterpret_cast<const char*>(a7), s3, sizeof(s3));
        SafeCopyCString(reinterpret_cast<const char*>(a8), s4, sizeof(s4));

        if (s1[0] && s3[0])
        {
            _snprintf_s(gAmmoFull, sizeof(gAmmoFull), _TRUNCATE,
                        "%s:%s\n%s:%s", s2, s1, s4, s3);
            gAmmoFullReady = true;
        }
    }

    return oAmmoFmt(obj, dst, size, fmt, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19,
                    a20, a21, a22, a23, a24, a25, a26, a27, a28);
}

static void AmmoFmtObserver(const char* fmt, const void* const* args, size_t count)
{
    if (!gInAmmoBoxInfo || count < 4 || !fmt || !FormatIsTwoLinePair(fmt))
        return;

    char s1[80] = {}, s2[80] = {}, s3[80] = {}, s4[80] = {};
    SafeCopyCString(reinterpret_cast<const char*>(args[0]), s1, sizeof(s1));
    SafeCopyCString(reinterpret_cast<const char*>(args[1]), s2, sizeof(s2));
    SafeCopyCString(reinterpret_cast<const char*>(args[2]), s3, sizeof(s3));
    SafeCopyCString(reinterpret_cast<const char*>(args[3]), s4, sizeof(s4));

    if (s1[0] && s3[0])
    {
        _snprintf_s(gAmmoFull, sizeof(gAmmoFull), _TRUNCATE, "%s:%s\n%s:%s", s2, s1, s4, s3);
        gAmmoFullReady = true;
    }
}

bool SetStringSystemSnprintfObserver(void(*observer)(const char* fmt, const void* const* args, size_t count));

static void EnsureAmmoFmtHook(void* self)
{
    if (gAmmoFmtHookState.load() != 0)
        return;

    int expected = 0;
    if (!gAmmoFmtHookState.compare_exchange_strong(expected, 1))
        return;

    if (SetStringSystemSnprintfObserver(&AmmoFmtObserver))
    {
        gAmmoFmtHookState.store(2);
        Log("[AmmoBox] format observer registered on the shared snprintf hook\n");
        return;
    }

    void* uiHost = nullptr;
    void* strObj = nullptr;
    void* vt = nullptr;
    void* fn = nullptr;

    if (SafeReadPtr(reinterpret_cast<char*>(self) + OFF_AMMOBOX_UIHOST, uiHost) && uiHost &&
        SafeReadPtr(reinterpret_cast<char*>(uiHost) + 0x30, strObj) && strObj &&
        SafeReadPtr(strObj, vt) && vt &&
        SafeReadPtr(reinterpret_cast<char*>(vt) + 0x18, fn) && fn)
    {
        if (MH_CreateHook(fn, &hkAmmoFmt, reinterpret_cast<void**>(&oAmmoFmt)) == MH_OK &&
            MH_EnableHook(fn) == MH_OK)
        {
            gTargetAmmoFmt = fn;
            gAmmoFmtHookState.store(2);
            Log("[AmmoBox] format hook installed at %p\n", fn);
            return;
        }
        Log("[AmmoBox] format hook FAILED at %p\n", fn);
    }
    else
    {
        Log("[AmmoBox] could not resolve format function.\n");
    }

    gAmmoFmtHookState.store(3);
}

static void ReRenderAmmoBoxText(void* self)
{
    void* node = nullptr;
    void* uiHost = nullptr;
    void* uiObj = nullptr;
    void* p3 = nullptr;
    void* vt = nullptr;
    void* fn = nullptr;

    if (!SafeReadPtr(reinterpret_cast<char*>(self) + OFF_AMMOBOX_NODE, node) || !node)
        return;
    if (!SafeReadPtr(reinterpret_cast<char*>(self) + OFF_AMMOBOX_UIHOST, uiHost) || !uiHost)
        return;
    if (!SafeReadPtr(reinterpret_cast<char*>(uiHost) + 0x20, uiObj) || !uiObj)
        return;
    if (!SafeReadPtr(reinterpret_cast<char*>(self) + OFF_AMMOBOX_PARAM3, p3))
        return;
    if (!SafeReadPtr(uiObj, vt) || !vt)
        return;
    if (!SafeReadPtr(reinterpret_cast<char*>(vt) + 0x738, fn) || !fn)
        return;

    __try
    {
        reinterpret_cast<AmmoBoxText_t>(fn)(uiObj, node, p3, 2, gAmmoFull, 0, 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void __fastcall hkAmmoBoxInfo(void* self)
{
    if (!self || !IsArabicSafe())
    {
        oAmmoBoxInfo(self);
        return;
    }

    EnsureAmmoFmtHook(self);

    gAmmoFullReady = false;
    gInAmmoBoxInfo = true;
    oAmmoBoxInfo(self);
    gInAmmoBoxInfo = false;

    if (gAmmoFullReady)
        ReRenderAmmoBoxText(self);
}

static std::atomic<int> gSideFobDiagBudget{ 24 };

static void DiagSideFobNode(void* node, const char* label)
{
    if (!node || gSideFobDiagBudget.load() <= 0)
        return;

    char buf[128] = {};
    if (!NodeFirstText(node, buf, sizeof(buf)))
        return;

    float textW = 0.0f;
    SafeReadF(reinterpret_cast<char*>(node) + OFF_TEXT_WIDTH, textW);

    const float dispW = gGetDisplayW ? gGetDisplayW(node) : 0.0f;

    uint8_t align = 0;
    uint8_t driver = 0;
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, align);
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, driver);

    gSideFobDiagBudget.fetch_sub(1);

    LogDetail("[SideFob] %s node=%p d8=%u da=%u textW=%.2f dispW=%.2f arabic=%d text=[%s]\n",
        label, node,
        static_cast<unsigned>(align), static_cast<unsigned>(driver),
        textW, dispW, NodeTextIsArabic(node) ? 1 : 0, buf);
}

static void AlignSideFobInfoNode(void* self, size_t nodeOffset, const char* label)
{
    void* node = nullptr;
    if (!SafeReadPtr(reinterpret_cast<char*>(self) + nodeOffset, node) || !node)
        return;

    DiagSideFobNode(node, label);

    if (!NodeTextIsArabic(node))
        return;

    uint8_t lineBefore = 0, blockBefore = 0, lineAfter = 0, blockAfter = 0, flags = 0;
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, lineBefore);
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, blockBefore);
    if (SafeReadU8(reinterpret_cast<char*>(node) + OFF_NODE_FLAGS, flags) && !(flags & NODE_FLAG_STENCIL))
        ForceNodeRightAlignAlways(node);
    else
        ForceNodeRightAlignIfFits(node);
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, lineAfter);
    SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, blockAfter);
    if (lineAfter != lineBefore || blockAfter != blockBefore)
        RequestTextRebuild(node);
}

static void __fastcall hkSideFobInfoUpdate(void* self)
{
    oSideFobInfoUpdate(self);

    if (!self || !IsArabicSafe())
        return;

    AlignSideFobInfoNode(self, OFF_SIDEFOB_NAME_A, "name.A");
    AlignSideFobInfoNode(self, OFF_SIDEFOB_NAME_B, "name.B");
    AlignSideFobInfoNode(self, OFF_SIDEFOB_CAPTION_A, "caption.A");
    AlignSideFobInfoNode(self, OFF_SIDEFOB_CAPTION_B, "caption.B");
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


void ArabicScrollStampRtlNode(void* node)
{
    if (!node)
        return;

    std::lock_guard<std::mutex> lk(gRtlMtx);
    if (gRtl.find(node) == gRtl.end())
        gRtl[node] = 0.0f;
}

bool NodeShowsArabicText(void* node)
{
    return node && (TextSetAsArabic(node) || NodeTextIsArabic(node));
}

void ArabicScrollUnstampRtlNode(void* node)
{
    if (!node)
        return;

    std::lock_guard<std::mutex> lk(gRtlMtx);
    ReleaseRtlNodeLocked(node);
}

void ArabicScrollReleaseFittingNode(void* node)
{
    if (!node)
        return;

    std::lock_guard<std::mutex> lk(gRtlMtx);
    ReleaseRtlNodeLocked(node);
}

static void ForceStampRtlNode(void* node)
{
    if (!node)
        return;

    std::lock_guard<std::mutex> lk(gRtlMtx);
    if (gRtl.find(node) == gRtl.end())
        gRtl[node] = 0.0f;
}

static bool IsModelNodeText(void* node, void* textVtable)
{
    void* vtable = nullptr;
    return textVtable && SafeReadPtr(node, vtable) && vtable == textVtable;
}

static void RestoreEquipDetailsAfterArabic(void* self)
{
    {
        std::lock_guard<std::mutex> lk(gEquipClassMtx);
        if (gEquipOrigAlign.empty())
            return;
    }

    void* const textVtable = GetModelNodeTextVtable();
    for (size_t off = 0; off < kEquipDetailScanEnd; off += sizeof(void*))
    {
        void* node = nullptr;
        if (!SafeReadPtr(reinterpret_cast<char*>(self) + off, node) || !node || !IsModelNodeText(node, textVtable))
            continue;

        EquipOriginalAlign orig{};
        {
            std::lock_guard<std::mutex> lk(gEquipClassMtx);
            auto it = gEquipOrigAlign.find(node);
            if (it == gEquipOrigAlign.end())
                continue;
            orig = it->second;
            gEquipOrigAlign.erase(it);
            gEquipClass.erase(node);
        }

        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN, orig.line);
        SafeWriteU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, orig.block);
        MarkNodeMoved(node);
        ArabicScrollReleaseFittingNode(node);
    }
}

static void __fastcall hkEquipDetails(void* self)
{
    oEquipDetails(self);

    if (!self)
        return;

    if (!IsArabicSafe())
    {
        RestoreEquipDetailsAfterArabic(self);
        return;
    }

    void* seen[192] = {};
    size_t seenCount = 0;

    const int pass = gEquipPassCounter.fetch_add(1);
    void* const textVtable = GetModelNodeTextVtable();

    for (size_t off = 0; off < kEquipDetailScanEnd; off += sizeof(void*))
    {
        void* node = nullptr;
        if (!SafeReadPtr(reinterpret_cast<char*>(self) + off, node) || !node)
            continue;

        if (!IsModelNodeText(node, textVtable) || !NodeIsConfirmedText(node))
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
        uint8_t daBefore = 0xFF;
        SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, d8Before);
        SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN_DRIVER, daBefore);
        RememberOriginalAlign(node, d8Before, daBefore);

        bool anyArabic = false;
        bool anyNonEmpty = false;
        const char* sample = nullptr;
        NodeTextSurvey(node, anyArabic, anyNonEmpty, sample);

        if (anyArabic)
            SetEquipNodeClass(node, EQUIP_ARABIC);
        else if (anyNonEmpty)
            SetEquipNodeClass(node, EQUIP_LATIN);

        const int cls = GetEquipNodeClass(node);

        if (cls == EQUIP_LATIN)
        {
            RestoreEquipNodeVanilla(node);
        }
        else
        {
            ForceNodeRightAlignIfFits(node);
            ForceStampRtlNode(node);
        }

        uint8_t d8After = 0xFF;
        SafeReadU8(reinterpret_cast<char*>(node) + OFF_ALIGN, d8After);

        if (gAmmoDiagBudget.load() > 0 && RL_DiagnosticsEnabled())
        {
            gAmmoDiagBudget.fetch_sub(1);

            char textCopy[64] = {};
            if (sample)
                SafeCopyCString(sample, textCopy, sizeof(textCopy));

            LogDetail("[AmmoDiag] pass=%d off=0x%zX node=%p T=%.2f W=%.2f ovf=%d d8=%u->%u cls=%d text=%s\n",
                pass, off, node, T, W, (W > 0.0f && T > W) ? 1 : 0,
                static_cast<unsigned>(d8Before), static_cast<unsigned>(d8After), cls,
                textCopy[0] ? textCopy : "(none)");
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

    gIsArab = &RL_IsRightToLeft;


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

    if (gAddr.MbDvcTrackListRecordStart != 0 && gAddr.MbDvcTrackListRecordStartVtSlot != 0)
    {
        auto* slot = reinterpret_cast<uintptr_t*>(ToRuntimeVA(hGame, gAddr.MbDvcTrackListRecordStartVtSlot));
        const uintptr_t expected = ToRuntimeVA(hGame, gAddr.MbDvcTrackListRecordStart);
        void* current = nullptr;
        if (SafeReadPtr(slot, current) && reinterpret_cast<uintptr_t>(current) == expected &&
            SwapPointer(slot, reinterpret_cast<uintptr_t>(&hkTrackRecordStart)))
        {
            gTrackRecordStartVtSlot = slot;
            oTrackRecordStart = reinterpret_cast<TrackRecordStart_t>(expected);
            Log("[ArabScroll] Track-list row right-align enabled through the record Start slot (V_FrameWork hooks the row text).\n");
        }
        else
        {
            Log("[ArabScroll] Track-list record Start slot is not what this build should have - left alone.\n");
        }
    }

    if (gAddr.MainListRecordCallFunc_RefreshName != 0)
    {
        gTargetStaffRowName = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.MainListRecordCallFunc_RefreshName));
        static const uint8_t kStaffRowNamePrologue[] = { 0x4C, 0x8B, 0xDC, 0x53, 0x57, 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00 };
        if (gTargetStaffRowName &&
            std::memcmp(gTargetStaffRowName, kStaffRowNamePrologue, sizeof(kStaffRowNamePrologue)) == 0 &&
            MH_CreateHook(gTargetStaffRowName, &hkStaffRowName,
                          reinterpret_cast<void**>(&oStaffRowName)) == MH_OK &&
            MH_EnableHook(gTargetStaffRowName) == MH_OK)
        {
            Log("[ArabScroll] Staff-list row name right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Staff-list row name hook failed.\n");
            gTargetStaffRowName = nullptr;
        }
    }

    if (gAddr.StaffListCallbackImpl_SetSectionInfoText != 0)
    {
        gTargetSectionInfo = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.StaffListCallbackImpl_SetSectionInfoText));
        static const uint8_t kSectionInfoPrologue[] = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x42, 0x40, 0x4C, 0x8B, 0xD9 };
        if (gTargetSectionInfo &&
            std::memcmp(gTargetSectionInfo, kSectionInfoPrologue, sizeof(kSectionInfoPrologue)) == 0 &&
            MH_CreateHook(gTargetSectionInfo, &hkSectionInfoText,
                          reinterpret_cast<void**>(&oSectionInfoText)) == MH_OK &&
            MH_EnableHook(gTargetSectionInfo) == MH_OK)
        {
            Log("[ArabScroll] Staff unit description right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Staff unit description hook failed.\n");
            gTargetSectionInfo = nullptr;
        }
    }

    if (gAddr.StaffListCallbackImpl_RefreshStaffDetails != 0)
    {
        gTargetStaffDetails = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.StaffListCallbackImpl_RefreshStaffDetails));
        static const uint8_t kStaffDetailsPrologue[] = { 0x4C, 0x8B, 0xDC, 0x53, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B, 0x91, 0xD0, 0x68, 0x00, 0x00 };
        if (gTargetStaffDetails &&
            std::memcmp(gTargetStaffDetails, kStaffDetailsPrologue, sizeof(kStaffDetailsPrologue)) == 0 &&
            MH_CreateHook(gTargetStaffDetails, &hkStaffDetails,
                          reinterpret_cast<void**>(&oStaffDetails)) == MH_OK &&
            MH_EnableHook(gTargetStaffDetails) == MH_OK)
        {
            Log("[ArabScroll] Staff details name right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Staff details name hook failed.\n");
            gTargetStaffDetails = nullptr;
        }
    }

    if (gAddr.BaseFacilities_RefreshDescription != 0)
    {
        gTargetBaseFacilityInfo = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.BaseFacilities_RefreshDescription));
        static const uint8_t kBaseFacilityPrologue[] = { 0x4C, 0x8B, 0xDC, 0x55, 0x41, 0x56, 0x49, 0x8D, 0x6B, 0xA1, 0x48, 0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00 };
        if (gTargetBaseFacilityInfo &&
            std::memcmp(gTargetBaseFacilityInfo, kBaseFacilityPrologue, sizeof(kBaseFacilityPrologue)) == 0 &&
            MH_CreateHook(gTargetBaseFacilityInfo, &hkBaseFacilityInfo,
                          reinterpret_cast<void**>(&oBaseFacilityInfo)) == MH_OK &&
            MH_EnableHook(gTargetBaseFacilityInfo) == MH_OK)
        {
            Log("[ArabScroll] Base facilities description right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Base facilities description hook failed.\n");
            gTargetBaseFacilityInfo = nullptr;
        }
    }

    if (gAddr.ResourceManagement_RefreshDescription != 0)
    {
        gTargetResourceInfo = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.ResourceManagement_RefreshDescription));
        static const uint8_t kResourceInfoPrologue[] = { 0x40, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0x91, 0xE8, 0x08, 0x00, 0x00 };
        if (gTargetResourceInfo &&
            std::memcmp(gTargetResourceInfo, kResourceInfoPrologue, sizeof(kResourceInfoPrologue)) == 0 &&
            MH_CreateHook(gTargetResourceInfo, &hkResourceInfo,
                          reinterpret_cast<void**>(&oResourceInfo)) == MH_OK &&
            MH_EnableHook(gTargetResourceInfo) == MH_OK)
        {
            Log("[ArabScroll] Resources description right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Resources description hook failed.\n");
            gTargetResourceInfo = nullptr;
        }
    }

    if (gAddr.AnnouncePopupBodyStart != 0 && gAddr.AnnouncePopupBodyStartVtSlot != 0)
    {
        auto* slot = reinterpret_cast<uintptr_t*>(ToRuntimeVA(hGame, gAddr.AnnouncePopupBodyStartVtSlot));
        const uintptr_t expected = ToRuntimeVA(hGame, gAddr.AnnouncePopupBodyStart);
        void* current = nullptr;
        if (SafeReadPtr(slot, current) && reinterpret_cast<uintptr_t>(current) == expected &&
            SwapPointer(slot, reinterpret_cast<uintptr_t>(&hkAnnouncePopupStart)))
        {
            gAnnounceVtSlot = slot;
            oAnnouncePopupStart = reinterpret_cast<AnnouncePopupStart_t>(expected);
            Log("[ArabScroll] Announcement popup title/body right-align enabled (vtable slot, V_FrameWork's Start hook kept).\n");
        }
        else
        {
            Log("[ArabScroll] Announcement popup vtable slot is not what this build should have - left alone.\n");
        }
    }

    if (gAddr.PopupEvCall_UpdatePopup != 0 && gAddr.UixSetTextForModelNodeTextImpl != 0)
    {
        void* updateTarget = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.PopupEvCall_UpdatePopup));
        void* setTextTarget = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.UixSetTextForModelNodeTextImpl));
        static const uint8_t kUpdatePopupPrologue[] = { 0x40, 0x53, 0x55, 0x57, 0x48, 0x83, 0xEC, 0x50, 0x33, 0xED, 0x48, 0x8B, 0xD9 };
        static const uint8_t kSetTextImplPrologue[] = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57, 0x48, 0x83, 0xEC, 0x70 };
        if (std::memcmp(updateTarget, kUpdatePopupPrologue, sizeof(kUpdatePopupPrologue)) == 0 &&
            std::memcmp(setTextTarget, kSetTextImplPrologue, sizeof(kSetTextImplPrologue)) == 0 &&
            MH_CreateHook(setTextTarget, &hkUixSetTextImpl, reinterpret_cast<void**>(&oUixSetTextImpl)) == MH_OK &&
            MH_CreateHook(updateTarget, &hkUpdatePopup, reinterpret_cast<void**>(&oUpdatePopup)) == MH_OK &&
            MH_EnableHook(setTextTarget) == MH_OK && MH_EnableHook(updateTarget) == MH_OK)
        {
            gTargetUixSetTextImpl = setTextTarget;
            gTargetUpdatePopup = updateTarget;
            Log("[ArabScroll] Event popup (PopupEvCall) title/body right-align hook enabled.\n");
        }
        else
        {
            MH_DisableHook(setTextTarget);
            MH_RemoveHook(setTextTarget);
            MH_DisableHook(updateTarget);
            MH_RemoveHook(updateTarget);
            Log("[ArabScroll] Event popup hook failed.\n");
        }
    }

    if (gAddr.UixPrefabTextCallFunc != 0)
    {
        void* target = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.UixPrefabTextCallFunc));
        static const uint8_t kPrefabTextPrologue[] = { 0x40, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x89, 0x74, 0x24, 0x58, 0x48, 0x8B, 0xF9 };
        if (std::memcmp(target, kPrefabTextPrologue, sizeof(kPrefabTextPrologue)) == 0 &&
            MH_CreateHook(target, &hkPrefabTextCallFunc, reinterpret_cast<void**>(&oPrefabTextCallFunc)) == MH_OK &&
            MH_EnableHook(target) == MH_OK)
        {
            gTargetPrefabTextCallFunc = target;
            Log("[ArabScroll] Prefab popup box text (confirmation popups) RTL mirror hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Prefab popup box text hook failed.\n");
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

    if (gAddr.TppUIPickUpPanel_UpdateAmmoBoxInfo != 0)
    {
        gTargetAmmoBoxInfo = reinterpret_cast<void*>(
            ToRuntimeVA(hGame, gAddr.TppUIPickUpPanel_UpdateAmmoBoxInfo));
        if (gTargetAmmoBoxInfo &&
            MH_CreateHook(gTargetAmmoBoxInfo, &hkAmmoBoxInfo,
                          reinterpret_cast<void**>(&oAmmoBoxInfo)) == MH_OK &&
            MH_EnableHook(gTargetAmmoBoxInfo) == MH_OK)
            Log("[AmmoBox] UpdateAmmoBoxInfo diagnostic hook enabled.\n");
        else
        {
            Log("[AmmoBox] UpdateAmmoBoxInfo hook failed.\n");
            gTargetAmmoBoxInfo = nullptr;
        }
    }

    if (gAddr.TppUISideFobInfo_Update != 0)
    {
        gTargetSideFobInfo = reinterpret_cast<void*>(
            ToRuntimeVA(hGame, gAddr.TppUISideFobInfo_Update));
        if (gTargetSideFobInfo &&
            MH_CreateHook(gTargetSideFobInfo, &hkSideFobInfoUpdate,
                          reinterpret_cast<void**>(&oSideFobInfoUpdate)) == MH_OK &&
            MH_EnableHook(gTargetSideFobInfo) == MH_OK)
        {
            Log("[ArabScroll] Quest-area banner right-align hook enabled.\n");
        }
        else
        {
            Log("[ArabScroll] Quest-area banner hook failed.\n");
            gTargetSideFobInfo = nullptr;
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
    if (gTargetStaffRowName) { MH_DisableHook(gTargetStaffRowName); MH_RemoveHook(gTargetStaffRowName); gTargetStaffRowName = nullptr; }
    if (gTargetSectionInfo) { MH_DisableHook(gTargetSectionInfo); MH_RemoveHook(gTargetSectionInfo); gTargetSectionInfo = nullptr; }
    if (gTargetStaffDetails) { MH_DisableHook(gTargetStaffDetails); MH_RemoveHook(gTargetStaffDetails); gTargetStaffDetails = nullptr; }
    if (gTargetBaseFacilityInfo) { MH_DisableHook(gTargetBaseFacilityInfo); MH_RemoveHook(gTargetBaseFacilityInfo); gTargetBaseFacilityInfo = nullptr; }
    if (gTargetResourceInfo) { MH_DisableHook(gTargetResourceInfo); MH_RemoveHook(gTargetResourceInfo); gTargetResourceInfo = nullptr; }
    if (gAnnounceVtSlot && oAnnouncePopupStart)
        SwapPointer(gAnnounceVtSlot, reinterpret_cast<uintptr_t>(oAnnouncePopupStart));
    if (gTrackRecordStartVtSlot && oTrackRecordStart)
        SwapPointer(gTrackRecordStartVtSlot, reinterpret_cast<uintptr_t>(oTrackRecordStart));
    gTrackRecordStartVtSlot = nullptr;
    gAnnounceVtSlot = nullptr;
    if (gTargetUpdatePopup) { MH_DisableHook(gTargetUpdatePopup); MH_RemoveHook(gTargetUpdatePopup); gTargetUpdatePopup = nullptr; }
    if (gTargetUixSetTextImpl) { MH_DisableHook(gTargetUixSetTextImpl); MH_RemoveHook(gTargetUixSetTextImpl); gTargetUixSetTextImpl = nullptr; }
    if (gTargetPrefabTextCallFunc) { MH_DisableHook(gTargetPrefabTextCallFunc); MH_RemoveHook(gTargetPrefabTextCallFunc); gTargetPrefabTextCallFunc = nullptr; }
    if (gTargetPlayerPanel) { MH_DisableHook(gTargetPlayerPanel); MH_RemoveHook(gTargetPlayerPanel); gTargetPlayerPanel = nullptr; }
    if (gTargetSideFobInfo) { MH_DisableHook(gTargetSideFobInfo); MH_RemoveHook(gTargetSideFobInfo); gTargetSideFobInfo = nullptr; oSideFobInfoUpdate = nullptr; }
    if (gTargetAmmoBoxInfo) { MH_DisableHook(gTargetAmmoBoxInfo); MH_RemoveHook(gTargetAmmoBoxInfo); gTargetAmmoBoxInfo = nullptr; }
    if (gTargetAmmoFmt) { MH_DisableHook(gTargetAmmoFmt); MH_RemoveHook(gTargetAmmoFmt); gTargetAmmoFmt = nullptr; oAmmoFmt = nullptr; gAmmoFmtHookState.store(0); }
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
    oStaffRowName  = nullptr;
    oSectionInfoText = nullptr;
    oStaffDetails  = nullptr;
    oBaseFacilityInfo = nullptr;
    oResourceInfo  = nullptr;
    oAnnouncePopupStart = nullptr;
    oUpdatePopup = nullptr;
    oUixSetTextImpl = nullptr;
    oPlayerPanel   = nullptr;
    oAmmoBoxInfo   = nullptr;
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
    gRtlTextKey.clear();
    gRtlWritten.clear();

    {
        std::lock_guard<std::mutex> lk(gEquipClassMtx);
        gEquipClass.clear();
        gEquipOrigAlign.clear();
    }
}
