// GetPauseHelpLangBlockPath.cpp

#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"

// ------------------------------------------------------------
// Arabic language checker
// Uses the game's existing "is Arabic language" function.
// Returns true when the current game language is Arabic.
// ------------------------------------------------------------
typedef bool(__cdecl* IsArabLanguage_t)();
static IsArabLanguage_t IsArabLanguage = nullptr;

// ------------------------------------------------------------
// Address constants
// IDA_IMAGE_BASE is the executable preferred base.
// ABS_* values are absolute VAs from your dump.
// ------------------------------------------------------------
static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uintptr_t ABS_IsArabLanguage = 0x145F134E0ull;

// tpp::ui::menu::impl::MotherBaseDevicePauseHelpTableImpl::GetPauseHelpLangBlockPath
static constexpr uintptr_t ABS_GetPauseHelpLangBlockPath = 0x145DDE150ull;

// ------------------------------------------------------------
// Arabic PathIds you provided
// param_2 == 0 -> /Assets/tpp/pack/ui/lang/lang_tpp_mbhelp_....fpk
// param_2 != 0 -> /Assets/tpp/pack/ui/lang/lang_tpp_mbhelp_fob_cstm_....fpk
// ------------------------------------------------------------
static constexpr uint64_t ARABIC_MBHELP_PATH_ID = 0x52295940953024c8ull;
static constexpr uint64_t ARABIC_MBHELP_FOB_CSTM_PATH_ID = 0x522BE66B0D02D0CBull;

// ------------------------------------------------------------
// Helper to convert an IDA absolute VA into runtime VA
// using the actual loaded game module base.
// ------------------------------------------------------------
static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

// ------------------------------------------------------------
// Safe Arabic check
// Calls the game's language function with SEH protection.
// ------------------------------------------------------------
static __forceinline bool IsArabicSafe()
{
    if (!IsArabLanguage)
        return false;

    __try
    {
        return IsArabLanguage();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

// ------------------------------------------------------------
// Original function type
// RCX = this
// RDX = output PathId*
// R8B = param_2
// Returns the same output pointer.
// ------------------------------------------------------------
using GetPauseHelpLangBlockPath_t = uint64_t * (__fastcall*)(void* thisPtr, uint64_t* outPathId, char param2);
static GetPauseHelpLangBlockPath_t oGetPauseHelpLangBlockPath = nullptr;

static void* gTarget = nullptr;

// ------------------------------------------------------------
// Hook
// If language is Arabic:
//   - param_2 == 0  -> force ARABIC_MBHELP_PATH_ID
//   - param_2 != 0  -> force ARABIC_MBHELP_FOB_CSTM_PATH_ID
// Otherwise call original.
// ------------------------------------------------------------
static uint64_t* __fastcall hkGetPauseHelpLangBlockPath(void* thisPtr, uint64_t* outPathId, char param2)
{
    if (!outPathId)
    {
        if (oGetPauseHelpLangBlockPath)
            return oGetPauseHelpLangBlockPath(thisPtr, outPathId, param2);
        return nullptr;
    }

    if (IsArabicSafe())
    {
        if (param2 == 0)
        {
            *outPathId = ARABIC_MBHELP_PATH_ID;
            Log("[GetPauseHelpLangBlockPath] Arabic detected, forcing mbhelp PathId: 0x%llX\n",
                static_cast<unsigned long long>(ARABIC_MBHELP_PATH_ID));
        }
        else
        {
            *outPathId = ARABIC_MBHELP_FOB_CSTM_PATH_ID;
            Log("[GetPauseHelpLangBlockPath] Arabic detected, forcing mbhelp_fob_cstm PathId: 0x%llX\n",
                static_cast<unsigned long long>(ARABIC_MBHELP_FOB_CSTM_PATH_ID));
        }

        return outPathId;
    }

    if (oGetPauseHelpLangBlockPath)
        return oGetPauseHelpLangBlockPath(thisPtr, outPathId, param2);

    *outPathId = 0xFFFFFFFFFFFFFFFFull;
    return outPathId;
}

// ------------------------------------------------------------
// Install hook
// Resolves runtime addresses, creates the MinHook hook,
// and enables it.
// ------------------------------------------------------------
bool InstallGetPauseHelpLangBlockPathHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    IsArabLanguage = reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, ABS_IsArabLanguage));
    gTarget = reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_GetPauseHelpLangBlockPath));

    if (!gTarget)
        return false;

    if (MH_CreateHook(gTarget, &hkGetPauseHelpLangBlockPath,
        reinterpret_cast<LPVOID*>(&oGetPauseHelpLangBlockPath)) != MH_OK)
    {
        Log("[GetPauseHelpLangBlockPath] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[GetPauseHelpLangBlockPath] MH_EnableHook failed.\n");
        return false;
    }

    Log("[GetPauseHelpLangBlockPath] Hook enabled.\n");
    return true;
}

// ------------------------------------------------------------
// Remove hook
// Disables and removes the hook if installed.
// ------------------------------------------------------------
void RemoveGetPauseHelpLangBlockPathHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    oGetPauseHelpLangBlockPath = nullptr;
    Log("[GetPauseHelpLangBlockPath] Removed.\n");
}