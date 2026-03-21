// UnkLoadTppPartsLangFpk_ArabicFix.cpp
//
// Adds the missing Arabic lang_tpp_parts_*.fpk load.
//
// Strategy:
// - Hook ui::lang::UnkLoadTppPartsLangFpk
// - Call the original first
// - If current language is Arabic, call UiUtility vfunc +0x200
//   with a one-entry path array containing:
//     /Assets/tpp/pack/ui/lang/lang_tpp_parts_ara.fpk
//     0x522A3CC63BE9B275
//
// Why this is safer:
// - We do not reimplement the whole original function
// - We do not touch its internal "current hash" logic
// - We only append the missing Arabic parts pack after the stock path load

#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"

// ------------------------------------------------------------
// Address constants
// ------------------------------------------------------------

// Function: image base used by IDA absolute VAs.
// Params:
// - none
static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

// Function: target to hook.
// Params:
// - none
static constexpr uintptr_t ABS_UnkLoadTppPartsLangFpk = 0x14095CA10ull;

// Function: helper used by the original routine.
// Resolved from the call inside UnkLoadTppPartsLangFpk.
// Params:
// - none
static constexpr uintptr_t ABS_GetUiUtility = 0x140939A20ull;

// Function: Arabic-language helper from your working pattern.
// Params:
// - none
static constexpr uintptr_t ABS_IsArabLanguage = 0x145F134E0ull;

// Function: missing Arabic parts pack hash.
// Params:
// - none
static constexpr uint64_t HASH_LANG_TPP_PARTS_ARA_FPK = 0x522A3CC63BE9B275ull;

// ------------------------------------------------------------
// Helper structs
// ------------------------------------------------------------

// Function: minimal path-array state matching what the UiUtility
// load function expects.
//
// The original function stores:
// - count     at local_60 low 32
// - capacity  at local_60 high 32
// - data ptr  at local_58
//
// So the effective layout is:
//   uint32_t count;
//   uint32_t capacity;
//   void*    data;
//
// Params:
// - none
struct PathArrayState
{
    uint32_t  count;
    uint32_t  capacity;
    uint64_t* data;
};

static_assert(sizeof(PathArrayState) == 16, "PathArrayState must be 16 bytes");

// ------------------------------------------------------------
// Function typedefs
// ------------------------------------------------------------

// Function: original ui::lang::UnkLoadTppPartsLangFpk.
// Params:
// - none
using UnkLoadTppPartsLangFpk_t = void(__fastcall*)();

// Function: current-language helper.
// Params:
// - none
using IsArabLanguage_t = bool(__cdecl*)();

// Function: tpp::ui::utility::GetUiUtility.
// Params:
// - none
using GetUiUtility_t = void* (__fastcall*)();

// Function: UiUtility vfunc +0x200 used by the original function
// to load an array of path hashes.
// Params:
// - uiUtility: UiUtility instance
// - paths: path array state
using UiUtility_LoadPathArray_t = void(__fastcall*)(void* uiUtility, PathArrayState* paths);

// ------------------------------------------------------------
// Globals
// ------------------------------------------------------------

// Function: original trampoline.
// Params:
// - none
static UnkLoadTppPartsLangFpk_t oUnkLoadTppPartsLangFpk = nullptr;

// Function: resolved helpers.
// Params:
// - none
static IsArabLanguage_t gIsArabLanguage = nullptr;
static GetUiUtility_t   gGetUiUtility = nullptr;

// Function: target pointer storage.
// Params:
// - none
static void* gTargetUnkLoadTppPartsLangFpk = nullptr;

// ------------------------------------------------------------
// Function: ToRuntimeVA
// Converts an IDA absolute VA into a runtime VA using the game module.
// Params:
// - hGame: game module base
// - absVa: IDA absolute VA
// Returns:
// - runtime VA
// ------------------------------------------------------------

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

// ------------------------------------------------------------
// Function: GetVFunc
// Reads a virtual function pointer from an object's vtable by byte offset.
// Params:
// - obj: object instance
// - byteOffset: vtable byte offset such as 0x200
// Returns:
// - typed function pointer or nullptr
// ------------------------------------------------------------

template <typename T>
static T GetVFunc(void* obj, size_t byteOffset)
{
    if (!obj)
        return nullptr;

    auto*** p = reinterpret_cast<void***>(obj);
    if (!p || !*p)
        return nullptr;

    return reinterpret_cast<T>((*p)[byteOffset / sizeof(void*)]);
}

// ------------------------------------------------------------
// Function: IsArabicSafe
// Calls the game's Arabic-language helper safely.
// Params:
// - none
// Returns:
// - true if current language is Arabic
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: LoadArabicTppPartsLangFpk
// Loads the missing Arabic parts-lang pack using the same UiUtility
// virtual function the game already uses.
// Params:
// - none
// ------------------------------------------------------------

static void LoadArabicTppPartsLangFpk()
{
    if (!gGetUiUtility)
        return;

    void* uiUtility = nullptr;

    __try
    {
        uiUtility = gGetUiUtility();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    if (!uiUtility)
        return;

    UiUtility_LoadPathArray_t fnLoadPathArray =
        GetVFunc<UiUtility_LoadPathArray_t>(uiUtility, 0x200);

    if (!fnLoadPathArray)
        return;

    uint64_t arabicHash = HASH_LANG_TPP_PARTS_ARA_FPK;
    PathArrayState paths{};
    paths.count = 1;
    paths.capacity = 1;
    paths.data = &arabicHash;

    __try
    {
        fnLoadPathArray(uiUtility, &paths);
        Log("[UnkLoadTppPartsLangFpk] Arabic parts FPK loaded: 0x%llX\n",
            static_cast<unsigned long long>(arabicHash));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log("[UnkLoadTppPartsLangFpk] Exception while loading Arabic parts FPK.\n");
    }
}

// ------------------------------------------------------------
// Function: hkUnkLoadTppPartsLangFpk
// Runs the original function first, then appends the missing Arabic
// parts FPK when the current language is Arabic.
// Params:
// - none
// ------------------------------------------------------------

static void __fastcall hkUnkLoadTppPartsLangFpk()
{
    if (oUnkLoadTppPartsLangFpk)
        oUnkLoadTppPartsLangFpk();

    if (!IsArabicSafe())
        return;

    LoadArabicTppPartsLangFpk();
}

// ------------------------------------------------------------
// Function: InstallUnkLoadTppPartsLangFpkArabicFixHook
// Resolves helpers, creates the hook, and enables it.
// Params:
// - hGame: game module base
// Returns:
// - true on success
// ------------------------------------------------------------

bool InstallUnkLoadTppPartsLangFpkArabicFixHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, ABS_IsArabLanguage));

    gGetUiUtility =
        reinterpret_cast<GetUiUtility_t>(ToRuntimeVA(hGame, ABS_GetUiUtility));

    gTargetUnkLoadTppPartsLangFpk =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_UnkLoadTppPartsLangFpk));

    if (!gTargetUnkLoadTppPartsLangFpk)
    {
        Log("[UnkLoadTppPartsLangFpk] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetUnkLoadTppPartsLangFpk,
            reinterpret_cast<void*>(&hkUnkLoadTppPartsLangFpk),
            reinterpret_cast<void**>(&oUnkLoadTppPartsLangFpk));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[UnkLoadTppPartsLangFpk] MH_CreateHook failed: %d\n",
            static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetUnkLoadTppPartsLangFpk);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[UnkLoadTppPartsLangFpk] MH_EnableHook failed: %d\n",
            static_cast<int>(enableSt));
        return false;
    }

    Log("[UnkLoadTppPartsLangFpk] Arabic fix hook enabled.\n");
    return true;
}

// ------------------------------------------------------------
// Function: RemoveUnkLoadTppPartsLangFpkArabicFixHook
// Disables and removes the hook.
// Params:
// - none
// ------------------------------------------------------------

void RemoveUnkLoadTppPartsLangFpkArabicFixHook()
{
    if (gTargetUnkLoadTppPartsLangFpk)
    {
        MH_DisableHook(gTargetUnkLoadTppPartsLangFpk);
        MH_RemoveHook(gTargetUnkLoadTppPartsLangFpk);
        gTargetUnkLoadTppPartsLangFpk = nullptr;
    }

    oUnkLoadTppPartsLangFpk = nullptr;
    gIsArabLanguage = nullptr;
    gGetUiUtility = nullptr;

    Log("[UnkLoadTppPartsLangFpk] Arabic fix hook removed.\n");
}