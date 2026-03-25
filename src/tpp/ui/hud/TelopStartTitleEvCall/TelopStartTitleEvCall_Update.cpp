#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using tpp_ui_hud_TelopStartTitleEvCall_Update_t = void(__fastcall*)(void* thisPtr);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_hud_TelopStartTitleEvCall_Update_t gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update = nullptr;
    static void* gTarget = nullptr;
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

/* Reads one byte safely. addr = source address, out = destination byte. */
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

/* Writes one byte safely. addr = target address, value = byte to write. */
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

/* Forces the telop typing-direction flag to the RTL path. thisPtr = TelopStartTitleEvCall*. */
static void ForceArabicTypingDirection(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    // +0x189 is the flag that makes Update use GetUTF8TextFromBack(...)
    SafeWriteU8(base + 0x189, 1);
}

/* Hook for tpp::ui::hud::TelopStartTitleEvCall::Update(this). */
static void __fastcall hk_tpp_ui_hud_TelopStartTitleEvCall_Update(void* thisPtr)
{
    uint8_t originalDirection = 0;
    bool hadOriginalDirection = false;

    if (IsArabicSafe() && thisPtr)
    {
        hadOriginalDirection = SafeReadU8(reinterpret_cast<uint8_t*>(thisPtr) + 0x189, originalDirection);
        ForceArabicTypingDirection(thisPtr);
    }

    if (gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update)
        gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update(thisPtr);

    if (IsArabicSafe() && thisPtr && hadOriginalDirection)
    {
        SafeWriteU8(reinterpret_cast<uint8_t*>(thisPtr) + 0x189, originalDirection);
    }
}

/* Installs the Arabic telop typing-direction hook. hGame = game module handle. */
bool InstallTelopStartTitleEvCallUpdateArabicTypingDirectionHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.IsArabLanguage || !gAddr.TelopStartTitleEvCallUpdate)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.TelopStartTitleEvCallUpdate);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hk_tpp_ui_hud_TelopStartTitleEvCall_Update,
        reinterpret_cast<LPVOID*>(&gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update)) != MH_OK)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] MH_EnableHook failed.\n");
        return false;
    }

    Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] Arabic typing-direction hook enabled.\n");
    return true;
}

/* Removes the Arabic telop typing-direction hook. */
void RemoveTelopStartTitleEvCallUpdateArabicTypingDirectionHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update = nullptr;
    gIsArabLanguage = nullptr;

    Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] Arabic typing-direction hook removed.\n");
}