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
    using tpp_ui_menu_GameOverEvCall_UpdateSelectText_t =
        void(__fastcall*)(void* thisPtr);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_menu_GameOverEvCall_UpdateSelectText_t
        gOrig_tpp_ui_menu_GameOverEvCall_UpdateSelectText = nullptr;

    static void* gTarget = nullptr;

    static std::unordered_map<void*, uint8_t> gOriginalAlignCache;
    static std::mutex gAlignMutex;

    static constexpr uint8_t TEXT_ALIGN_LEFT = 0;
    static constexpr uint8_t TEXT_ALIGN_CENTER = 1;
    static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

    static constexpr size_t kModelNodeTextAlignOffset = 0xD8;

    static constexpr size_t kOptionCountOffset = 0x210;
    static constexpr size_t kOptionTextNodeBaseOffset = 0x2E0;
    static constexpr size_t kOptionStride = 0x48;
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

/* Reads a uint32 safely. Parameters: addr = source address, out = read result. */
static bool SafeReadU32(const void* addr, uint32_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint32_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
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
        Log("[tpp::ui::menu::GameOverEvCall::UpdateSelectText] Failed to write right alignment.\n");
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
        Log("[tpp::ui::menu::GameOverEvCall::UpdateSelectText] Failed to restore alignment.\n");
}

/* Applies Arabic alignment to all Game Over option text nodes. Parameters: thisPtr = GameOverEvCall*. */
static void ApplyArabicAlignmentToGameOverOptionNodes(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    uint32_t optionCount = 0;
    if (!SafeReadU32(base + kOptionCountOffset, optionCount))
        return;

    for (uint32_t i = 0; i < optionCount; ++i)
    {
        void* textNode = nullptr;
        const size_t nodeOffset = kOptionTextNodeBaseOffset + static_cast<size_t>(i) * kOptionStride;

        if (SafeReadPtr(base + nodeOffset, textNode) && textNode)
            ApplyArabicLeftToRightRule(textNode);
    }
}

/* Restores original alignment for all Game Over option text nodes. Parameters: thisPtr = GameOverEvCall*. */
static void RestoreAlignmentForGameOverOptionNodes(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    uint32_t optionCount = 0;
    if (!SafeReadU32(base + kOptionCountOffset, optionCount))
        return;

    for (uint32_t i = 0; i < optionCount; ++i)
    {
        void* textNode = nullptr;
        const size_t nodeOffset = kOptionTextNodeBaseOffset + static_cast<size_t>(i) * kOptionStride;

        if (SafeReadPtr(base + nodeOffset, textNode) && textNode)
            RestoreOriginalAlign(textNode);
    }
}

/* Hook for UpdateSelectText. Parameters: thisPtr = GameOverEvCall*. */
static void __fastcall hk_tpp_ui_menu_GameOverEvCall_UpdateSelectText(void* thisPtr)
{
    if (gOrig_tpp_ui_menu_GameOverEvCall_UpdateSelectText)
        gOrig_tpp_ui_menu_GameOverEvCall_UpdateSelectText(thisPtr);

    if (IsArabicSafe())
        ApplyArabicAlignmentToGameOverOptionNodes(thisPtr);
    else
        RestoreAlignmentForGameOverOptionNodes(thisPtr);
}

/* Installs the Game Over select text alignment hook. Parameters: hGame = unused, kept for project consistency. */
bool InstallGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.GameOverEvCall_UpdateSelectText)
    {
        Log("[tpp::ui::menu::GameOverEvCall::UpdateSelectText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.GameOverEvCall_UpdateSelectText);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hk_tpp_ui_menu_GameOverEvCall_UpdateSelectText,
        reinterpret_cast<LPVOID*>(&gOrig_tpp_ui_menu_GameOverEvCall_UpdateSelectText)) != MH_OK)
    {
        Log("[tpp::ui::menu::GameOverEvCall::UpdateSelectText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[tpp::ui::menu::GameOverEvCall::UpdateSelectText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[tpp::ui::menu::GameOverEvCall::UpdateSelectText] Arabic left->right align hook enabled.\n");
    return true;
}

/* Removes the Game Over select text alignment hook. Parameters: none. */
void RemoveGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrig_tpp_ui_menu_GameOverEvCall_UpdateSelectText = nullptr;
    gIsArabLanguage = nullptr;

    std::lock_guard<std::mutex> lock(gAlignMutex);
    gOriginalAlignCache.clear();

    Log("[tpp::ui::menu::GameOverEvCall::UpdateSelectText] Arabic left->right align hook removed.\n");
}