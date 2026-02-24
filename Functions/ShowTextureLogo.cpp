// ShowTextureLogo.cpp
#include "pch.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "ShowTextureLogo.h"

// -----------------------------------------------------------------------------
// Arabic language checker (user-provided)
// -----------------------------------------------------------------------------
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
static constexpr uintptr_t ABS_LogoThunk = 0x145C1CBC0ull;

static constexpr uint64_t KO_LOGO_TEXID = 0x156A4BD46CAF208Bull;
static constexpr uint64_t INVALID_TEXID = 0xFFFFFFFFFFFFFFFFull;
static constexpr uint32_t SPECIAL_STYLE_ID = 0x887C9A23;

static __forceinline void* ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return (void*)((uintptr_t)hGame + (absVa - IDA_IMAGE_BASE));
}

using LogoThunk_t = void(__fastcall*)(
    void* commonDataMgr,
    int showFlag,
    long long logoStrPtr,
    float timeSeconds,
    uint64_t texturePathId,
    uint32_t styleId
    );

static LogoThunk_t oLogoThunk = nullptr;
static void* gTargetThunk = nullptr;

static void __fastcall hkLogoThunk(
    void* commonDataMgr,
    int showFlag,
    long long logoStrPtr,
    float timeSeconds,
    uint64_t texturePathId,
    uint32_t styleId)
{
    if (!IsArabicSafe())
    {
        oLogoThunk(commonDataMgr, showFlag, logoStrPtr, timeSeconds, texturePathId, styleId);
        return;
    }
    Log("[ShowTextureLogo] Lang is Arabic, Show Kor.\n");
    if (showFlag == 1 &&
        styleId == SPECIAL_STYLE_ID &&
        logoStrPtr == 0 &&
        texturePathId == INVALID_TEXID)
    {
        texturePathId = KO_LOGO_TEXID;
    }

    oLogoThunk(commonDataMgr, showFlag, logoStrPtr, timeSeconds, texturePathId, styleId);
}

bool InstallShowTextureLogoHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    // Resolve Arabic checker (absolute VA -> runtime VA)
    IsArabLanguage = (IsArabLanguage_t)((uintptr_t)hGame + (ABS_IsArabLanguage - IDA_IMAGE_BASE));

    gTargetThunk = ToRuntimeVA(hGame, ABS_LogoThunk);
    if (!gTargetThunk)
        return false;

    if (MH_CreateHook(gTargetThunk, &hkLogoThunk, (LPVOID*)&oLogoThunk) != MH_OK)
        return false;

    if (MH_EnableHook(gTargetThunk) != MH_OK)
        return false;

    Log("[ShowTextureLogo] Hook enabled.\n");
    return true;
}

void RemoveShowTextureLogoHook()
{
    if (gTargetThunk)
    {
        MH_DisableHook(gTargetThunk);
        MH_RemoveHook(gTargetThunk);
        gTargetThunk = nullptr;
    }
    Log("[ShowTextureLogo] Removed.\n");
}