// LoadingTipsEv_UpdateActPhase_ArabicLeftToRightAlign.cpp

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
    using tpp_ui_menu_LoadingTipsEv_UpdateActPhase_t =
        void(__fastcall*)(void* thisPtr);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_menu_LoadingTipsEv_UpdateActPhase_t gOrig_tpp_ui_menu_LoadingTipsEv_UpdateActPhase = nullptr;
    static void* gTarget = nullptr;

    static std::unordered_map<void*, uint8_t> gOriginalAlignCache;
    static std::mutex gAlignMutex;

    static constexpr uint8_t TEXT_ALIGN_LEFT = 0;
    static constexpr uint8_t TEXT_ALIGN_CENTER = 1;
    static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

    static constexpr size_t kModelNodeTextAlignOffset = 0xD8;

    static constexpr size_t kTitleNodeOffset = 0x960;
    static constexpr size_t kBodyNodeOffset = 0x968;
    static constexpr size_t kPromptNodeOffset = 0x9E8;
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
        Log("[tpp::ui::menu::LoadingTipsEv::UpdateActPhase] Failed to write right alignment.\n");
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
        Log("[tpp::ui::menu::LoadingTipsEv::UpdateActPhase] Failed to restore alignment.\n");
}

/* Applies Arabic alignment to title, body, and prompt nodes. thisPtr = LoadingTipsEv*. */
static void ApplyArabicAlignmentToLoadingTipsNodes(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* titleNode = nullptr;
    void* bodyNode = nullptr;
    void* promptNode = nullptr;

    if (SafeReadPtr(base + kTitleNodeOffset, titleNode) && titleNode)
        ApplyArabicLeftToRightRule(titleNode);

    if (SafeReadPtr(base + kBodyNodeOffset, bodyNode) && bodyNode)
        ApplyArabicLeftToRightRule(bodyNode);

    if (SafeReadPtr(base + kPromptNodeOffset, promptNode) && promptNode)
        ApplyArabicLeftToRightRule(promptNode);
}

/* Restores original alignment for title, body, and prompt nodes. thisPtr = LoadingTipsEv*. */
static void RestoreAlignmentForLoadingTipsNodes(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* titleNode = nullptr;
    void* bodyNode = nullptr;
    void* promptNode = nullptr;

    if (SafeReadPtr(base + kTitleNodeOffset, titleNode) && titleNode)
        RestoreOriginalAlign(titleNode);

    if (SafeReadPtr(base + kBodyNodeOffset, bodyNode) && bodyNode)
        RestoreOriginalAlign(bodyNode);

    if (SafeReadPtr(base + kPromptNodeOffset, promptNode) && promptNode)
        RestoreOriginalAlign(promptNode);
}

/* Hook for tpp::ui::menu::LoadingTipsEv::UpdateActPhase(thisPtr). */
static void __fastcall hk_tpp_ui_menu_LoadingTipsEv_UpdateActPhase(void* thisPtr)
{
    if (gOrig_tpp_ui_menu_LoadingTipsEv_UpdateActPhase)
        gOrig_tpp_ui_menu_LoadingTipsEv_UpdateActPhase(thisPtr);

    if (IsArabicSafe())
        ApplyArabicAlignmentToLoadingTipsNodes(thisPtr);
    else
        RestoreAlignmentForLoadingTipsNodes(thisPtr);
}

/* Installs the LoadingTipsEv::UpdateActPhase Arabic left->right alignment hook. hGame kept for project consistency. */
bool InstallLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.LoadingTipsEv_UpdateActPhase)
    {
        Log("[tpp::ui::menu::LoadingTipsEv::UpdateActPhase] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.LoadingTipsEv_UpdateActPhase);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hk_tpp_ui_menu_LoadingTipsEv_UpdateActPhase,
        reinterpret_cast<LPVOID*>(&gOrig_tpp_ui_menu_LoadingTipsEv_UpdateActPhase)) != MH_OK)
    {
        Log("[tpp::ui::menu::LoadingTipsEv::UpdateActPhase] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[tpp::ui::menu::LoadingTipsEv::UpdateActPhase] MH_EnableHook failed.\n");
        return false;
    }

    Log("[tpp::ui::menu::LoadingTipsEv::UpdateActPhase] Arabic left->right align hook enabled.\n");
    return true;
}

/* Removes the LoadingTipsEv::UpdateActPhase Arabic left->right alignment hook. Takes no parameters. */
void RemoveLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrig_tpp_ui_menu_LoadingTipsEv_UpdateActPhase = nullptr;
    gIsArabLanguage = nullptr;

    std::lock_guard<std::mutex> lock(gAlignMutex);
    gOriginalAlignCache.clear();

    Log("[tpp::ui::menu::LoadingTipsEv::UpdateActPhase] Arabic left->right align hook removed.\n");
}