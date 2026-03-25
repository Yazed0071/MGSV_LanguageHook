#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

using IsArabLanguage_t = bool(__cdecl*)();
using SetupMenuText_t = void(__fastcall*)(void* thisPtr);
using SetMenuInfoText_t = void(__fastcall*)(void* thisPtr, void* item);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static SetupMenuText_t oSetupMenuText = nullptr;
static SetMenuInfoText_t oSetMenuInfoText = nullptr;

static void* gTargetSetupMenuText = nullptr;
static void* gTargetSetMenuInfoText = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

static constexpr size_t kMenuItemCountOffset = 0x288;
static constexpr size_t kMenuNodeCountOffset = 0xA40;
static constexpr size_t kMenuNodeArrayOffset = 0xA48;
static constexpr size_t kMenuNodeStride = 0x20;
static constexpr size_t kMenuTextNodeOffsetInEntry = 0x8;
static constexpr size_t kInfoTextNodeOffset = 0xA68;

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

static __forceinline bool IsArabicSafe()
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

static void ForceRightAlignNode(void* node)
{
    if (!node)
        return;

    SafeWriteU8(reinterpret_cast<uint8_t*>(node) + 0xD8, TEXT_ALIGN_RIGHT);
}

static void* GetPauseMenuTextNodeAt(void* thisPtr, uint32_t index)
{
    if (!thisPtr)
        return nullptr;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* arrayBase = nullptr;
    if (!SafeReadPtr(base + kMenuNodeArrayOffset, arrayBase) || !arrayBase)
        return nullptr;

    void* textNode = nullptr;
    SafeReadPtr(reinterpret_cast<uint8_t*>(arrayBase) + index * kMenuNodeStride + kMenuTextNodeOffsetInEntry, textNode);
    return textNode;
}

static void* GetPauseMenuInfoNode(void* thisPtr)
{
    if (!thisPtr)
        return nullptr;

    void* node = nullptr;
    SafeReadPtr(reinterpret_cast<uint8_t*>(thisPtr) + kInfoTextNodeOffset, node);
    return node;
}

static void ApplyPauseMenuListAlignment(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    uint32_t menuItemCount = 0;
    uint32_t nodeCount = 0;

    SafeReadU32(base + kMenuItemCountOffset, menuItemCount);
    SafeReadU32(base + kMenuNodeCountOffset, nodeCount);

    const uint32_t count = (menuItemCount < nodeCount) ? menuItemCount : nodeCount;

    for (uint32_t i = 0; i < count; ++i)
    {
        void* textNode = GetPauseMenuTextNodeAt(thisPtr, i);
        ForceRightAlignNode(textNode);
    }
}

static void ApplyPauseMenuInfoAlignment(void* thisPtr)
{
    void* node = GetPauseMenuInfoNode(thisPtr);
    ForceRightAlignNode(node);
}

static void __fastcall hkSetupMenuText(void* thisPtr)
{
    if (!oSetupMenuText)
        return;

    oSetupMenuText(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyPauseMenuListAlignment(thisPtr);
}

static void __fastcall hkSetMenuInfoText(void* thisPtr, void* item)
{
    if (!oSetMenuInfoText)
        return;

    if (IsArabicSafe())
        ApplyPauseMenuInfoAlignment(thisPtr);

    oSetMenuInfoText(thisPtr, item);

    if (!IsArabicSafe())
        return;

    ApplyPauseMenuInfoAlignment(thisPtr);
}

bool InstallGamePauseMenuArabicTextHooks(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTargetSetupMenuText =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetupMenuText));

    gTargetSetMenuInfoText =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetMenuInfoText));

    if (!gTargetSetupMenuText || !gTargetSetMenuInfoText)
    {
        Log("[GamePauseMenuAct] Failed to resolve targets.\n");
        return false;
    }

    MH_STATUS st = MH_CreateHook(
        gTargetSetupMenuText,
        reinterpret_cast<void*>(&hkSetupMenuText),
        reinterpret_cast<void**>(&oSetupMenuText));

    if (st != MH_OK && st != MH_ERROR_ALREADY_CREATED)
    {
        Log("[GamePauseMenuAct::SetupMenuText] MH_CreateHook failed: %d\n", static_cast<int>(st));
        return false;
    }

    st = MH_EnableHook(gTargetSetupMenuText);
    if (st != MH_OK && st != MH_ERROR_ENABLED)
    {
        MH_RemoveHook(gTargetSetupMenuText);
        oSetupMenuText = nullptr;
        Log("[GamePauseMenuAct::SetupMenuText] MH_EnableHook failed: %d\n", static_cast<int>(st));
        return false;
    }

    st = MH_CreateHook(
        gTargetSetMenuInfoText,
        reinterpret_cast<void*>(&hkSetMenuInfoText),
        reinterpret_cast<void**>(&oSetMenuInfoText));

    if (st != MH_OK && st != MH_ERROR_ALREADY_CREATED)
    {
        MH_DisableHook(gTargetSetupMenuText);
        MH_RemoveHook(gTargetSetupMenuText);
        oSetupMenuText = nullptr;
        Log("[GamePauseMenuAct::SetMenuInfoText] MH_CreateHook failed: %d\n", static_cast<int>(st));
        return false;
    }

    st = MH_EnableHook(gTargetSetMenuInfoText);
    if (st != MH_OK && st != MH_ERROR_ENABLED)
    {
        MH_DisableHook(gTargetSetMenuInfoText);
        MH_RemoveHook(gTargetSetMenuInfoText);
        oSetMenuInfoText = nullptr;

        MH_DisableHook(gTargetSetupMenuText);
        MH_RemoveHook(gTargetSetupMenuText);
        oSetupMenuText = nullptr;

        Log("[GamePauseMenuAct::SetMenuInfoText] MH_EnableHook failed: %d\n", static_cast<int>(st));
        return false;
    }

    Log("[GamePauseMenuAct] Arabic hooks enabled.\n");
    return true;
}

void RemoveGamePauseMenuArabicTextHooks()
{
    if (gTargetSetupMenuText)
    {
        MH_DisableHook(gTargetSetupMenuText);
        MH_RemoveHook(gTargetSetupMenuText);
        gTargetSetupMenuText = nullptr;
    }

    if (gTargetSetMenuInfoText)
    {
        MH_DisableHook(gTargetSetMenuInfoText);
        MH_RemoveHook(gTargetSetMenuInfoText);
        gTargetSetMenuInfoText = nullptr;
    }

    oSetupMenuText = nullptr;
    oSetMenuInfoText = nullptr;
    gIsArabLanguage = nullptr;
}