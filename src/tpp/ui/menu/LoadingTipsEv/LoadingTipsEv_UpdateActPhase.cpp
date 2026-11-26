// LoadingTipsEv_UpdateActPhase_ArabicLeftToRightAlign.cpp

#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

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

    static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

    static constexpr size_t kModelNodeTextAlignOffset = 0xD8;
    static constexpr size_t kModelNodeTextBlockAlignOffset = 0xDA;
    static constexpr size_t kModelNodeTextFlagsOffset = 0x90;
    static constexpr uint16_t kModelNodeTextRebuildFlag = 0x10;

    static constexpr size_t kBodyNodeOffset = 0x968;
    static constexpr uint32_t kBodyLeaseMs = 1000;
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

void KeepArabicLinesRightAligned(void* node);
void KeepArabicLinesRightAlignedWhileShown(void* node, uint32_t leaseMs);

static bool SetRightAndRequestRebuild(void* node)
{
    __try
    {
        auto* p = static_cast<uint8_t*>(node);
        if (p[kModelNodeTextAlignOffset] != TEXT_ALIGN_RIGHT)
        {
            p[kModelNodeTextAlignOffset] = TEXT_ALIGN_RIGHT;
            *reinterpret_cast<uint16_t*>(p + kModelNodeTextFlagsOffset) |= kModelNodeTextRebuildFlag;
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void ForceArabicBodyLinesRight(void* node)
{
    if (!node)
        return;

    CacheOriginalAlignIfNeeded(node);
    if (!SetRightAndRequestRebuild(node))
        return;
    KeepArabicLinesRightAligned(node);
    KeepArabicLinesRightAlignedWhileShown(node, kBodyLeaseMs);
}

void PrepareArabicLoadingTipBody(void* loadingTipsEv)
{
    void* bodyNode = nullptr;
    if (loadingTipsEv && SafeReadPtr(reinterpret_cast<uint8_t*>(loadingTipsEv) + kBodyNodeOffset, bodyNode) && bodyNode)
        ForceArabicBodyLinesRight(bodyNode);
}

static std::atomic<int> gBodyLogBudget{ 12 };
static std::atomic<void*> gLastBodyNode{ nullptr };
static std::atomic<int> gLastBodyAlign{ -1 };

static void NoteBodyAlignBeforeUpdate(void* thisPtr)
{
    if (!thisPtr || gBodyLogBudget.load() <= 0)
        return;

    void* bodyNode = nullptr;
    uint8_t align = 0;
    uint8_t blockAlign = 0;
    if (!SafeReadPtr(reinterpret_cast<uint8_t*>(thisPtr) + kBodyNodeOffset, bodyNode) || !bodyNode ||
        !SafeReadU8(reinterpret_cast<uint8_t*>(bodyNode) + kModelNodeTextAlignOffset, align) ||
        !SafeReadU8(reinterpret_cast<uint8_t*>(bodyNode) + kModelNodeTextBlockAlignOffset, blockAlign))
        return;

    if (gLastBodyNode.exchange(bodyNode) == bodyNode && gLastBodyAlign.exchange(align) == align)
        return;
    gLastBodyAlign.store(align);

    gBodyLogBudget.fetch_sub(1);
    Log("[tpp::ui::menu::LoadingTipsEv] body node %p at frame start: line align %u, block align %u\n",
        bodyNode, static_cast<unsigned>(align), static_cast<unsigned>(blockAlign));
}

static void ApplyArabicAlignmentToLoadingTipsNodes(void* thisPtr)
{
    PrepareArabicLoadingTipBody(thisPtr);
}

static void RestoreAlignmentForLoadingTipsNodes(void* thisPtr)
{
    void* bodyNode = nullptr;
    if (thisPtr && SafeReadPtr(reinterpret_cast<uint8_t*>(thisPtr) + kBodyNodeOffset, bodyNode) && bodyNode)
        RestoreOriginalAlign(bodyNode);
}

/* Hook for tpp::ui::menu::LoadingTipsEv::UpdateActPhase(thisPtr). */
static void __fastcall hk_tpp_ui_menu_LoadingTipsEv_UpdateActPhase(void* thisPtr)
{
    if (IsArabicSafe())
        NoteBodyAlignBeforeUpdate(thisPtr);

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

    const uintptr_t target = gAddr.LoadingTipsEv_Update ? gAddr.LoadingTipsEv_Update : gAddr.LoadingTipsEv_UpdateActPhase;
    const char* name = gAddr.LoadingTipsEv_Update ? "Update" : "UpdateActPhase";
    if (!gAddr.IsArabLanguage || !target)
    {
        Log("[tpp::ui::menu::LoadingTipsEv] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gTarget = reinterpret_cast<void*>(target);

    if (MH_CreateHook(
        gTarget,
        &hk_tpp_ui_menu_LoadingTipsEv_UpdateActPhase,
        reinterpret_cast<LPVOID*>(&gOrig_tpp_ui_menu_LoadingTipsEv_UpdateActPhase)) != MH_OK)
    {
        Log("[tpp::ui::menu::LoadingTipsEv::%s] MH_CreateHook failed.\n", name);
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[tpp::ui::menu::LoadingTipsEv::%s] MH_EnableHook failed.\n", name);
        return false;
    }

    Log("[tpp::ui::menu::LoadingTipsEv::%s] Arabic per-frame tip alignment hook enabled.\n", name);
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