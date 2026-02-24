// GetFtexPathId.cpp
#include "pch.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "GetFtexPathId.h"

typedef bool(__cdecl* IsArabLanguage_t)();
static IsArabLanguage_t IsArabLanguage = nullptr;
static constexpr uintptr_t ABS_IsArabLanguage = 0x145F134E0ull;

static __forceinline bool IsArabicSafe()
{
    if (!IsArabLanguage)
        return false;
    __try { return IsArabLanguage(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uintptr_t ABS_GetFtexPathId = 0x1408D05F0ull;

static constexpr bool ARABIC_FORCE_KO_LANGUAGE = true;
static constexpr int  FORCED_LANGUAGE_ID = 0xCE7D2A71; // Korean language id from your dump

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return (uintptr_t)hGame + (absVa - IDA_IMAGE_BASE);
}

using GetFtexPathId_t = void(__fastcall*)(void* param_1, uint64_t* chapterTexture, uint8_t chapterCode, int language);
static GetFtexPathId_t oGetFtexPathId = nullptr;

static void __fastcall hkGetFtexPathId(void* param_1, uint64_t* chapterTexture, uint8_t chapterCode, int language)
{
    if (!chapterTexture || !oGetFtexPathId)
        return;

    uint8_t idx = (chapterCode > 3) ? 0 : chapterCode;

    const bool isArabic = IsArabicSafe();

    if (isArabic && ARABIC_FORCE_KO_LANGUAGE)
    {
        Log("[GetFtexPathId] Lang is Arabic, Show Kor.\n");
        oGetFtexPathId(param_1, chapterTexture, idx, FORCED_LANGUAGE_ID);
        return;
    }

    oGetFtexPathId(param_1, chapterTexture, idx, language);
}

// Install/remove
static void* gTarget = nullptr;

bool InstallGetFtexPathIdHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    // Resolve Arabic checker (absolute VA -> runtime VA)
    IsArabLanguage = (IsArabLanguage_t)ToRuntimeVA(hGame, ABS_IsArabLanguage);

    gTarget = (void*)ToRuntimeVA(hGame, ABS_GetFtexPathId);
    if (!gTarget)
        return false;

    if (MH_CreateHook(gTarget, &hkGetFtexPathId, (LPVOID*)&oGetFtexPathId) != MH_OK)
        return false;

    if (MH_EnableHook(gTarget) != MH_OK)
        return false;

    Log("[GetFtexPathId] Hook enabled.\n");
    return true;
}

void RemoveGetFtexPathIdHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    Log("[GetFtexPathId] Removed.\n");
}