// CallLogView_ArabicLeftToRightAlign.cpp

#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <unordered_map>
#include <mutex>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using tpp_ui_hud_AnnounceLogViewer_CallLogView_t =
        void(__fastcall*)(void* thisPtr, char* text, char param3, uint8_t slot, char param5);

    using GetUix_t = void*(__cdecl*)();
    using UixSetNodeFloat_t = void(__fastcall*)(void* self, void* node, float value);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_hud_AnnounceLogViewer_CallLogView_t gOrig_tpp_ui_hud_AnnounceLogViewer_CallLogView = nullptr;
    static void* gTarget = nullptr;
    static GetUix_t gGetUix = nullptr;

    static std::unordered_map<void*, uint8_t> gOriginalAlignCache;
    static std::mutex gAlignMutex;

    static int gBarDiagBudget = 80;

    static std::unordered_map<void*, float> gBarBaseX;

    static constexpr uint8_t TEXT_ALIGN_LEFT = 0;
    static constexpr uint8_t TEXT_ALIGN_CENTER = 1;
    static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;
    static constexpr size_t kModelNodeTextAlignOffset = 0xD8;

    // LogModel slot fields (stride 0x58): +0x18 text node A, +0x20 text node B,
    static constexpr size_t kSlotStride = 0x58;
    static constexpr size_t kSlotTextNodeA = 0x18;
    static constexpr size_t kSlotBarNode = 0x30;
    static constexpr size_t kSlotRevealMetric = 0x54;

    // Quark node fields: +0x00 layout anchor X, +0x20 local translation (x,y,z),
    static constexpr size_t kNodeAnchorX = 0x00;
    static constexpr size_t kNodeTransX = 0x20;
    static constexpr size_t kNodeSizeW = 0x40;
    static constexpr size_t kNodeMeasuredW = 0x17C;

    // GetUixUtilityToFeedQuarkEnvironment vtable byte offset (15.4 EN): SetPosX.
    static constexpr size_t kVtSetPosX = 0x350;

    // Reveal metric -> wipe width, matching CallLogView: metric * 0.1 + 0.5.
    static constexpr float kRevealScale = 0.1f;
    static constexpr float kRevealBias = 0.5f;

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

static bool SafeReadFloat(const void* addr, float& out)
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

static bool CacheOriginalAlignIfNeeded(void* node)
{
    if (!node)
        return false;

    uint8_t align = 0;
    if (!SafeReadU8(reinterpret_cast<uint8_t*>(node) + kModelNodeTextAlignOffset, align))
        return false;

    std::lock_guard<std::mutex> lock(gAlignMutex);
    if (gOriginalAlignCache.find(node) == gOriginalAlignCache.end())
        gOriginalAlignCache.emplace(node, align);

    return true;
}

static bool GetCachedOriginalAlign(void* node, uint8_t& out)
{
    std::lock_guard<std::mutex> lock(gAlignMutex);

    const auto it = gOriginalAlignCache.find(node);
    if (it == gOriginalAlignCache.end())
        return false;

    out = it->second;
    return true;
}

static void ApplyArabicLeftToRightRule(void* node)
{
    if (!node)
        return;

    if (!CacheOriginalAlignIfNeeded(node))
        return;

    uint8_t originalAlign = 0;
    if (!GetCachedOriginalAlign(node, originalAlign))
        return;

    if (originalAlign != TEXT_ALIGN_LEFT)
        return;

    if (!SafeWriteU8(reinterpret_cast<uint8_t*>(node) + kModelNodeTextAlignOffset, TEXT_ALIGN_RIGHT))
        Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] Failed to write right alignment.\n");
}

static void RestoreOriginalAlign(void* node)
{
    if (!node)
        return;

    if (!CacheOriginalAlignIfNeeded(node))
        return;

    uint8_t originalAlign = 0;
    if (!GetCachedOriginalAlign(node, originalAlign))
        return;

    if (!SafeWriteU8(reinterpret_cast<uint8_t*>(node) + kModelNodeTextAlignOffset, originalAlign))
        Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] Failed to restore alignment.\n");
}

static void ApplyArabicAlignmentToSlot(void* thisPtr, uint8_t slot)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    const size_t slotOff = static_cast<size_t>(slot) * kSlotStride;

    void* nodeA = nullptr;
    void* nodeB = nullptr;

    if (SafeReadPtr(base + slotOff + kSlotTextNodeA, nodeA) && nodeA)
        ApplyArabicLeftToRightRule(nodeA);

    if (SafeReadPtr(base + slotOff + 0x20, nodeB) && nodeB)
        ApplyArabicLeftToRightRule(nodeB);
}

static void RestoreAlignmentForSlot(void* thisPtr, uint8_t slot)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    const size_t slotOff = static_cast<size_t>(slot) * kSlotStride;

    void* nodeA = nullptr;
    void* nodeB = nullptr;

    if (SafeReadPtr(base + slotOff + kSlotTextNodeA, nodeA) && nodeA)
        RestoreOriginalAlign(nodeA);

    if (SafeReadPtr(base + slotOff + 0x20, nodeB) && nodeB)
        RestoreOriginalAlign(nodeB);
}

static void* GetUixSafe()
{
    if (!gGetUix)
        return nullptr;

    __try
    {
        return gGetUix();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
}

static bool GetBarBaseX(void* barNode, float& out)
{
    std::lock_guard<std::mutex> lock(gAlignMutex);

    const auto it = gBarBaseX.find(barNode);
    if (it != gBarBaseX.end())
    {
        out = it->second;
        return true;
    }

    float current = 0.0f;
    if (!SafeReadFloat(reinterpret_cast<uint8_t*>(barNode) + kNodeTransX, current))
        return false;

    gBarBaseX.emplace(barNode, current);
    out = current;
    return true;
}

static void SetBarPosX(void* uix, void* barNode, float x)
{
    __try
    {
        void** vt = *reinterpret_cast<void***>(uix);
        auto setPos = reinterpret_cast<UixSetNodeFloat_t>(vt[kVtSetPosX / sizeof(void*)]);
        setPos(uix, barNode, x);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static void ApplyArabicBarRightAnchor(void* thisPtr, uint8_t slot)
{
    if (!thisPtr || !gGetUix)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    const size_t slotOff = static_cast<size_t>(slot) * kSlotStride;

    void* textNode = nullptr;
    void* barNode = nullptr;
    if (!SafeReadPtr(base + slotOff + kSlotTextNodeA, textNode) || !textNode)
        return;
    if (!SafeReadPtr(base + slotOff + kSlotBarNode, barNode) || !barNode)
        return;

    float textAnchorX = 0.0f;
    float textTransX = 0.0f;
    float boxW = 0.0f;
    float barAnchorX = 0.0f;
    float measuredW = 0.0f;
    float revealMetric = 0.0f;

    if (!SafeReadFloat(reinterpret_cast<uint8_t*>(textNode) + kNodeAnchorX, textAnchorX))
        return;
    SafeReadFloat(reinterpret_cast<uint8_t*>(textNode) + kNodeTransX, textTransX);
    if (!SafeReadFloat(reinterpret_cast<uint8_t*>(textNode) + kNodeSizeW, boxW))
        return;
    if (!SafeReadFloat(reinterpret_cast<uint8_t*>(barNode) + kNodeAnchorX, barAnchorX))
        return;
    SafeReadFloat(reinterpret_cast<uint8_t*>(textNode) + kNodeMeasuredW, measuredW);
    SafeReadFloat(base + slotOff + kSlotRevealMetric, revealMetric);

    if (!(boxW > 1.0f) || boxW > 100000.0f)
        return;

    const float rightEdge = textAnchorX + textTransX + boxW;

    float tw = measuredW;
    if (!(tw > 0.0f) || tw > 100000.0f)
        tw = boxW;

    float baseX = 0.0f;
    if (!GetBarBaseX(barNode, baseX))
        return;

    const float shiftText = (rightEdge - tw) - barAnchorX;
    float setPosX = baseX + shiftText * kRevealScale;

    const float limit = boxW;
    if (setPosX < -limit)
        setPosX = -limit;
    if (setPosX > limit)
        setPosX = limit;

    void* uix = GetUixSafe();
    if (!uix)
        return;

    SetBarPosX(uix, barNode, setPosX);

    if (gBarDiagBudget > 0)
    {
        gBarDiagBudget--;
        const float ws = revealMetric * kRevealScale + kRevealBias;
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "[BarFix] slot=%u rtl=1 ws=%.2f measW=%.2f boxW=%.2f base=%.2f shiftText=%.2f setX=%.2f\n",
            static_cast<unsigned>(slot), ws, measuredW, boxW, baseX, shiftText, setPosX);
        Log(buf);
    }
}

static void RestoreBarForSlot(void* thisPtr, uint8_t slot)
{
    if (!thisPtr || !gGetUix)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    const size_t slotOff = static_cast<size_t>(slot) * kSlotStride;

    void* barNode = nullptr;
    if (!SafeReadPtr(base + slotOff + kSlotBarNode, barNode) || !barNode)
        return;

    float baseX = 0.0f;
    if (!GetBarBaseX(barNode, baseX))
        return;

    void* uix = GetUixSafe();
    if (!uix)
        return;

    SetBarPosX(uix, barNode, baseX);
}

/* tpp::ui::hud::AnnounceLogViewer::CallLogView(thisPtr, text, param3, slot, param5). */
static void __fastcall hk_tpp_ui_hud_AnnounceLogViewer_CallLogView(
    void* thisPtr,
    char* text,
    char param3,
    uint8_t slot,
    char param5)
{
    if (gOrig_tpp_ui_hud_AnnounceLogViewer_CallLogView)
        gOrig_tpp_ui_hud_AnnounceLogViewer_CallLogView(thisPtr, text, param3, slot, param5);

    if (IsArabicSafe())
    {
        ApplyArabicAlignmentToSlot(thisPtr, slot);
        ApplyArabicBarRightAnchor(thisPtr, slot);
    }
    else
    {
        RestoreAlignmentForSlot(thisPtr, slot);
        RestoreBarForSlot(thisPtr, slot);
    }
}

/* CallLogView Arabic left->right alignment hook. hGame kept for project consistency. */
bool InstallAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.IsArabLanguage || !gAddr.CallLogView)
    {
        Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.CallLogView);
    gGetUix = reinterpret_cast<GetUix_t>(gAddr.GetUixUtilityToFeedQuarkEnvironment);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hk_tpp_ui_hud_AnnounceLogViewer_CallLogView,
        reinterpret_cast<LPVOID*>(&gOrig_tpp_ui_hud_AnnounceLogViewer_CallLogView)) != MH_OK)
    {
        Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] MH_EnableHook failed.\n");
        return false;
    }

    if (!gGetUix)
        Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] Bar anchor disabled (no Uix host address).\n");

    Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] Arabic LEFT->RIGHT alignment hook enabled.\n");
    return true;
}

void RemoveAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(gAlignMutex);
        gOriginalAlignCache.clear();
        gBarBaseX.clear();
    }

    gOrig_tpp_ui_hud_AnnounceLogViewer_CallLogView = nullptr;
    gIsArabLanguage = nullptr;
    gGetUix = nullptr;

    Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] Arabic LEFT->RIGHT alignment hook removed.\n");
}
