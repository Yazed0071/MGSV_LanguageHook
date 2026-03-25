// CallLogView_ArabicLeftToRightAlign.cpp

#include "pch.h"
#include <Windows.h>
#include <cstdint>
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

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_hud_AnnounceLogViewer_CallLogView_t gOrig_tpp_ui_hud_AnnounceLogViewer_CallLogView = nullptr;
    static void* gTarget = nullptr;

    static std::unordered_map<void*, uint8_t> gOriginalAlignCache;
    static std::mutex gAlignMutex;

    static constexpr uint8_t TEXT_ALIGN_LEFT = 0;
    static constexpr uint8_t TEXT_ALIGN_CENTER = 1;
    static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;
    static constexpr size_t kModelNodeTextAlignOffset = 0xD8;
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

/* Reads a pointer safely. addr = source address, out = read result. */
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

/* Reads one byte safely. addr = source address, out = read result. */
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

/* Writes one byte safely. addr = destination address, value = value to write. */
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

/* Caches the original alignment for a text node once. node = ModelNodeText*. */
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

/* Gets the cached original alignment. node = ModelNodeText*, out = original alignment. */
static bool GetCachedOriginalAlign(void* node, uint8_t& out)
{
    std::lock_guard<std::mutex> lock(gAlignMutex);

    const auto it = gOriginalAlignCache.find(node);
    if (it == gOriginalAlignCache.end())
        return false;

    out = it->second;
    return true;
}

/* Applies LEFT -> RIGHT only. node = ModelNodeText*. */
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

/* Restores the original cached alignment. node = ModelNodeText*. */
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

/* Applies Arabic alignment rule to both slot text nodes. thisPtr = AnnounceLogViewer*, slot = slot index. */
static void ApplyArabicAlignmentToSlot(void* thisPtr, uint8_t slot)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    const size_t slotOff = static_cast<size_t>(slot) * 0x58;

    void* nodeA = nullptr;
    void* nodeB = nullptr;

    if (SafeReadPtr(base + slotOff + 0x18, nodeA) && nodeA)
        ApplyArabicLeftToRightRule(nodeA);

    if (SafeReadPtr(base + slotOff + 0x20, nodeB) && nodeB)
        ApplyArabicLeftToRightRule(nodeB);
}

/* Restores original alignment on both slot text nodes. thisPtr = AnnounceLogViewer*, slot = slot index. */
static void RestoreAlignmentForSlot(void* thisPtr, uint8_t slot)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    const size_t slotOff = static_cast<size_t>(slot) * 0x58;

    void* nodeA = nullptr;
    void* nodeB = nullptr;

    if (SafeReadPtr(base + slotOff + 0x18, nodeA) && nodeA)
        RestoreOriginalAlign(nodeA);

    if (SafeReadPtr(base + slotOff + 0x20, nodeB) && nodeB)
        RestoreOriginalAlign(nodeB);
}

/* Hook for tpp::ui::hud::AnnounceLogViewer::CallLogView(thisPtr, text, param3, slot, param5). */
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
        ApplyArabicAlignmentToSlot(thisPtr, slot);
    else
        RestoreAlignmentForSlot(thisPtr, slot);
}

/* Installs the CallLogView Arabic left->right alignment hook. hGame kept for project consistency. */
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

    Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] Arabic LEFT->RIGHT alignment hook enabled.\n");
    return true;
}

/* Removes the CallLogView hook and clears cached node alignment. */
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
    }

    gOrig_tpp_ui_hud_AnnounceLogViewer_CallLogView = nullptr;
    gIsArabLanguage = nullptr;

    Log("[tpp::ui::hud::AnnounceLogViewer::CallLogView] Arabic LEFT->RIGHT alignment hook removed.\n");
}