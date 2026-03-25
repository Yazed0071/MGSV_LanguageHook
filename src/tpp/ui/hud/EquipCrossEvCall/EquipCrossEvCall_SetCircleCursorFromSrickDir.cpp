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

    using tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir_t =
        void(__fastcall*)(void* thisPtr, uint32_t param2, uint32_t param3, uint8_t param4);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir_t
        gOrig_tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir = nullptr;

    static void* gTarget = nullptr;

    static std::unordered_map<void*, uint8_t> gOriginalAlignCache;
    static std::mutex gAlignMutex;

    static constexpr uint8_t TEXT_ALIGN_LEFT = 0;
    static constexpr uint8_t TEXT_ALIGN_CENTER = 1;
    static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

    static constexpr size_t kModelNodeTextAlignOffset = 0xD8;

    static constexpr size_t kMainNameNodeOffset = 0x218;
    static constexpr size_t kBodyNodeOffset = 0x220;
    static constexpr size_t kFallbackNodeOffset = 0x228;
}

/* Checks Arabic state safely. Parameters: none. */
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

/* Reads a pointer safely. Parameters: addr = source address, out = read result. */
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

/* Reads one byte safely. Parameters: addr = source address, out = read result. */
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

/* Writes one byte safely. Parameters: addr = destination address, value = value to write. */
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

/* Caches the original alignment for a node once. Parameters: node = ModelNodeText*. */
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

/* Gets the cached original alignment. Parameters: node = ModelNodeText*, out = cached value. */
static bool GetCachedOriginalAlign(void* node, uint8_t& out)
{
    std::lock_guard<std::mutex> lock(gAlignMutex);

    const auto it = gOriginalAlignCache.find(node);
    if (it == gOriginalAlignCache.end())
        return false;

    out = it->second;
    return true;
}

/* Applies LEFT -> RIGHT only. Parameters: node = ModelNodeText*. */
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
        Log("[tpp::ui::hud::EquipCrossEvCall::SetCircleCursorFromSrickDir] Failed to write right alignment.\n");
}

/* Restores the original cached alignment. Parameters: node = ModelNodeText*. */
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
        Log("[tpp::ui::hud::EquipCrossEvCall::SetCircleCursorFromSrickDir] Failed to restore alignment.\n");
}

/* Applies Arabic alignment to the EquipCross nodes. Parameters: thisPtr = EquipCrossEvCall*. */
static void ApplyArabicAlignmentToEquipCrossNodes(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* bodyNode = nullptr;
    if (SafeReadPtr(base + kBodyNodeOffset, bodyNode) && bodyNode)
        ApplyArabicLeftToRightRule(bodyNode);

    void* mainNameNode = nullptr;
    if (SafeReadPtr(base + kMainNameNodeOffset, mainNameNode) && mainNameNode)
        ApplyArabicLeftToRightRule(mainNameNode);

    // void* fallbackNode = nullptr;
    // if (SafeReadPtr(base + kFallbackNodeOffset, fallbackNode) && fallbackNode)
    //     ApplyArabicLeftToRightRule(fallbackNode);
}

/* Restores original alignment for the EquipCross nodes. Parameters: thisPtr = EquipCrossEvCall*. */
static void RestoreAlignmentForEquipCrossNodes(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* bodyNode = nullptr;
    if (SafeReadPtr(base + kBodyNodeOffset, bodyNode) && bodyNode)
        RestoreOriginalAlign(bodyNode);

    void* mainNameNode = nullptr;
    if (SafeReadPtr(base + kMainNameNodeOffset, mainNameNode) && mainNameNode)
        RestoreOriginalAlign(mainNameNode);

    // void* fallbackNode = nullptr;
    // if (SafeReadPtr(base + kFallbackNodeOffset, fallbackNode) && fallbackNode)
    //     RestoreOriginalAlign(fallbackNode);
}

/* Hook for SetCircleCursorFromSrickDir. Parameters: thisPtr = EquipCrossEvCall*, param2/3/4 = original args. */
static void __fastcall hk_tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir(
    void* thisPtr,
    uint32_t param2,
    uint32_t param3,
    uint8_t param4)
{
    if (gOrig_tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir)
    {
        gOrig_tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir(
            thisPtr,
            param2,
            param3,
            param4);
    }

    if (IsArabicSafe())
        ApplyArabicAlignmentToEquipCrossNodes(thisPtr);
    else
        RestoreAlignmentForEquipCrossNodes(thisPtr);
}

/* Installs the EquipCross alignment hook. Parameters: hGame = unused, kept for project consistency. */
bool InstallEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.EquipCrossEvCall_SetCircleCursorFromSrickDir)
    {
        Log("[tpp::ui::hud::EquipCrossEvCall::SetCircleCursorFromSrickDir] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.EquipCrossEvCall_SetCircleCursorFromSrickDir);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hk_tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir,
        reinterpret_cast<LPVOID*>(&gOrig_tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir)) != MH_OK)
    {
        Log("[tpp::ui::hud::EquipCrossEvCall::SetCircleCursorFromSrickDir] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[tpp::ui::hud::EquipCrossEvCall::SetCircleCursorFromSrickDir] MH_EnableHook failed.\n");
        return false;
    }

    Log("[tpp::ui::hud::EquipCrossEvCall::SetCircleCursorFromSrickDir] Arabic left->right align hook enabled.\n");
    return true;
}

/* Removes the EquipCross alignment hook. Parameters: none. */
void RemoveEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrig_tpp_ui_hud_EquipCrossEvCall_SetCircleCursorFromSrickDir = nullptr;
    gIsArabLanguage = nullptr;

    std::lock_guard<std::mutex> lock(gAlignMutex);
    gOriginalAlignCache.clear();

    Log("[tpp::ui::hud::EquipCrossEvCall::SetCircleCursorFromSrickDir] Arabic left->right align hook removed.\n");
}