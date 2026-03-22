#include <Windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

// Function: original fox::ui::lang::Init.
// Params:
// - none
using UiLangInit_t = void(__cdecl*)();

// Function: fox::File::RegisterLoadFunc used by lang init.
// Params:
// - tmp: temporary local buffer/context
// - ext: extension to register
// - handler: engine callback pointer
using FileRegisterLoadFunc_t = void(__fastcall*)(void* tmp, const char* ext, void* handler);

static UiLangInit_t oUiLangInit = nullptr;
static FileRegisterLoadFunc_t gFileRegisterLoadFunc = nullptr;
static void* gLangLoadFuncHandler = nullptr;
static void* gTargetUiLangInit = nullptr;

// Function: image base used by stored absolute VAs.
// Params:
// - none
static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

// Function: convert stored absolute VA to runtime VA.
// Params:
// - hGame: game module base
// - absVa: stored IDA absolute VA
// Returns:
// - runtime address
static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

// Function: register one extra lang extension.
// Params:
// - ext: extension string like ".cht.lng"
static void RegisterExtraLangExt(const char* ext)
{
    if (!gFileRegisterLoadFunc || !gLangLoadFuncHandler || !ext)
        return;

    uint8_t tmp[32]{};
    gFileRegisterLoadFunc(tmp, ext, gLangLoadFuncHandler);

    Log("[UiLangInit] Registered extra lang extension: %s\n", ext);
}

// Function: detour for fox::ui::lang::Init.
// Params:
// - none
static void __cdecl hkUiLangInit()
{
    if (oUiLangInit)
        oUiLangInit();

    RegisterExtraLangExt(".cht.lng");
    RegisterExtraLangExt(".kor.lng");
    RegisterExtraLangExt(".cht.lng2");
    RegisterExtraLangExt(".kor.lng2");
}

// Function: installs the fox::ui::lang::Init hook.
// Params:
// - hGame: game module base
// Returns:
// - true on success
bool InstallUiLangInitExtraLoadFuncsHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (gAddr.UiLangInit == 0 ||
        gAddr.FileRegisterLoadFunc == 0 ||
        gAddr.LangLoadFuncHandler == 0)
    {
        Log("[UiLangInit] Required addresses missing for this build.\n");
        return false;
    }

    gFileRegisterLoadFunc =
        reinterpret_cast<FileRegisterLoadFunc_t>(
            ToRuntimeVA(hGame, gAddr.FileRegisterLoadFunc));

    gLangLoadFuncHandler =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.LangLoadFuncHandler));

    gTargetUiLangInit =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.UiLangInit));

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetUiLangInit,
            reinterpret_cast<void*>(&hkUiLangInit),
            reinterpret_cast<void**>(&oUiLangInit));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[UiLangInit] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetUiLangInit);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[UiLangInit] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[UiLangInit] Extra .cht/.kor lang registrations enabled.\n");
    return true;
}

// Function: removes the fox::ui::lang::Init hook.
// Params:
// - none
void RemoveUiLangInitExtraLoadFuncsHook()
{
    if (gTargetUiLangInit)
    {
        MH_DisableHook(gTargetUiLangInit);
        MH_RemoveHook(gTargetUiLangInit);
        gTargetUiLangInit = nullptr;
    }

    oUiLangInit = nullptr;
    gFileRegisterLoadFunc = nullptr;
    gLangLoadFuncHandler = nullptr;

    Log("[UiLangInit] Extra .cht/.kor lang registrations removed.\n");
}