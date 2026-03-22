// GetTipsLangBlockPath.cpp

#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
// ------------------------------------------------------------
// Arabic language checker
// ------------------------------------------------------------

typedef bool(__cdecl* IsArabLanguage_t)();
static IsArabLanguage_t IsArabLanguage = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

// Your Arabic PathId
static constexpr uint64_t ARABIC_TIPS_LANG_BLOCK_PATH_ID = 0x5228b8f2da5ea9aeull;

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return (uintptr_t)hGame + (absVa - IDA_IMAGE_BASE);
}

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
// RDX = out PathId buffer
// Return = same out buffer
// ------------------------------------------------------------

using GetTipsLangBlockPath_t = uint64_t * (__fastcall*)(void* thisPtr, uint64_t* outPathId);
static GetTipsLangBlockPath_t oGetTipsLangBlockPath = nullptr;

static void* gTarget = nullptr;

// ------------------------------------------------------------
// Hook
// ------------------------------------------------------------

static uint64_t* __fastcall hkGetTipsLangBlockPath(void* thisPtr, uint64_t* outPathId)
{
    if (!outPathId)
        return oGetTipsLangBlockPath ? oGetTipsLangBlockPath(thisPtr, outPathId) : nullptr;

    if (IsArabicSafe())
    {
        *outPathId = ARABIC_TIPS_LANG_BLOCK_PATH_ID;
        Log("[GetTipsLangBlockPath] Arabic detected, forcing PathId: 0x%llX\n",
            static_cast<unsigned long long>(ARABIC_TIPS_LANG_BLOCK_PATH_ID));
        return outPathId;
    }

    if (oGetTipsLangBlockPath)
        return oGetTipsLangBlockPath(thisPtr, outPathId);

    *outPathId = 0xFFFFFFFFFFFFFFFFull;
    return outPathId;
}

// ------------------------------------------------------------
// Install / remove
// ------------------------------------------------------------

bool InstallGetTipsLangBlockPathHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    IsArabLanguage = reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));
    gTarget = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.GetTipsLangBlockPath));

    if (!gTarget)
        return false;

    if (MH_CreateHook(gTarget, &hkGetTipsLangBlockPath, reinterpret_cast<LPVOID*>(&oGetTipsLangBlockPath)) != MH_OK)
    {
        Log("[GetTipsLangBlockPath] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[GetTipsLangBlockPath] MH_EnableHook failed.\n");
        return false;
    }

    Log("[GetTipsLangBlockPath] Hook enabled.\n");
    return true;
}

void RemoveGetTipsLangBlockPathHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    oGetTipsLangBlockPath = nullptr;
    Log("[GetTipsLangBlockPath] Removed.\n");
}