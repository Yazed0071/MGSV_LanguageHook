#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using UpdateInformationTextBox_t = void(__fastcall*)(void* thisPtr);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static UpdateInformationTextBox_t gOrigUpdateInformationTextBox = nullptr;
    static void* gTarget = nullptr;

    static constexpr uint8_t kAlignLeft = 0;
    static constexpr uint8_t kAlignCenter = 1;
    static constexpr uint8_t kAlignRight = 2;

    static constexpr ptrdiff_t kInfoNodeOffset = 0x1528;
    static constexpr ptrdiff_t kNodeAlignmentOffset = 0xD8;
}

/* Checks Arabic state safely. */
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

/* Reads a pointer safely. */
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

/* Writes one byte safely. */
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

/* Forces the Side Ops information textbox node alignment. */
static bool ForceInformationTextBoxAlignment(void* thisPtr, uint8_t alignValue)
{
    if (!thisPtr)
        return false;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* infoNode = nullptr;
    if (!SafeReadPtr(base + kInfoNodeOffset, infoNode) || !infoNode)
        return false;

    return SafeWriteU8(reinterpret_cast<uint8_t*>(infoNode) + kNodeAlignmentOffset, alignValue);
}

/* Hook for MbDvcSideOpsCallbackImpl::UpdateInformationTextBox(this). */
static void __fastcall hkMbDvcSideOpsCallbackImpl_UpdateInformationTextBox(void* thisPtr)
{
    if (!gOrigUpdateInformationTextBox)
        return;

    if (!IsArabicSafe())
    {
        gOrigUpdateInformationTextBox(thisPtr);
        return;
    }

    // Force before original in case the engine reads alignment while building.
    ForceInformationTextBoxAlignment(thisPtr, kAlignRight);

    gOrigUpdateInformationTextBox(thisPtr);

    // Force again after original in case the function resets/rebuilds the node.
    ForceInformationTextBoxAlignment(thisPtr, kAlignRight);
}

/* Installs the Side Ops information textbox Arabic alignment hook. */
bool InstallMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.MbDvcSideOpsCallbackImpl_UpdateInformationTextBox)
    {
        Log("[MbDvcSideOpsCallbackImpl::UpdateInformationTextBox] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.MbDvcSideOpsCallbackImpl_UpdateInformationTextBox);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkMbDvcSideOpsCallbackImpl_UpdateInformationTextBox,
        reinterpret_cast<LPVOID*>(&gOrigUpdateInformationTextBox)) != MH_OK)
    {
        Log("[MbDvcSideOpsCallbackImpl::UpdateInformationTextBox] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[MbDvcSideOpsCallbackImpl::UpdateInformationTextBox] MH_EnableHook failed.\n");
        return false;
    }

    Log("[MbDvcSideOpsCallbackImpl::UpdateInformationTextBox] Arabic alignment hook enabled.\n");
    return true;
}

/* Removes the Side Ops information textbox Arabic alignment hook. */
void RemoveMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigUpdateInformationTextBox = nullptr;
    gIsArabLanguage = nullptr;

    Log("[MbDvcSideOpsCallbackImpl::UpdateInformationTextBox] Arabic alignment hook removed.\n");
}