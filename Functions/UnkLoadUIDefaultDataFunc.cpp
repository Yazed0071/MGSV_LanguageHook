#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include "MinHook.h"
#include "UnkLoadUIDefaultDataFunc.h"

// ----------------------------------------
// Opaque engine structs (enough for our use)
// ----------------------------------------
struct FoxString
{
    union {
        char  sso[16];
        char* heapPtr;
    } Data;

    uint64_t Length;    // +0x10
    uint64_t Capacity;  // +0x18
};

struct FoxPath
{
    uint64_t q[3];      // size 0x18 (opaque)
};

// ----------------------------------------
// Helpers
// ----------------------------------------
static uintptr_t GetExeBase()
{
    return reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
}

// Convert absolute VA -> RVA assuming preferred image base 0x140000000
static constexpr uintptr_t EXE_PREFERRED_BASE = 0x140000000ull;
static constexpr uintptr_t ToRva(uintptr_t absAddr)
{
    return absAddr - EXE_PREFERRED_BASE;
}

// ----------------------------------------
// User-provided function
// ----------------------------------------
typedef bool(__cdecl* IsArabLanguage_t)();
static IsArabLanguage_t IsArabLanguage = nullptr;

// ----------------------------------------
// Engine function pointer types
// ----------------------------------------
using FoxStringCtor_t = void(__fastcall*)(FoxString* self, const char* cstr);
using StdFree_t = void(__fastcall*)(void* data, uint64_t unk);
using PathCInitWithString_t = void(__fastcall*)(FoxPath* out, void* strObj, void* maybeBase);
using PathAssign_t = FoxPath * (__fastcall*)(FoxPath* self, const FoxPath* rhs);
using LoadPageBlock_t = void(__fastcall*)(void* p1, void* p2, void* p3);
using PathDtor_t = void(__fastcall*)(FoxPath* self);

using UnkLoadUIDefaultDataFunc_t = void(__fastcall*)(void* p1, void* p2, void* p3);

// ----------------------------------------
// Addresses (ABS from your dump)
// ----------------------------------------
static constexpr uintptr_t ABS_IsArabLanguage = 0x145F134E0ull;
static constexpr uintptr_t ABS_UnkLoadFunc = 0x145F86420ull;

// TODO: Replace these placeholders with your real addresses
static constexpr uintptr_t ABS_FoxStringCtor = 0x1400163F0ull;
static constexpr uintptr_t ABS_StdFree = 0x140004200ull;
static constexpr uintptr_t ABS_PathCInit = 0x140085780ull;
static constexpr uintptr_t ABS_PathAssign = 0x140085650ull;
static constexpr uintptr_t ABS_PathDtor = 0x140085610ull;
static constexpr uintptr_t ABS_LoadPageBlock = 0x140928D10ull;

// ----------------------------------------
// Resolved pointers
// ----------------------------------------
static FoxStringCtor_t       FoxStringCtor = nullptr;
static StdFree_t             StdFree = nullptr;
static PathCInitWithString_t PathCInitWithString = nullptr;
static PathAssign_t          PathAssign = nullptr;
static PathDtor_t            PathDtor = nullptr;
static LoadPageBlock_t       LoadPageBlock = nullptr;

static UnkLoadUIDefaultDataFunc_t g_Orig = nullptr;

// If destructor on param_3 causes issues, set to 0
#ifndef DESTROY_PARAM3
#define DESTROY_PARAM3 1
#endif

// ----------------------------------------
// Hook implementation
// ----------------------------------------
static void __fastcall hkUnkLoadUIDefaultDataFunc(void* param_1, void* param_2, void* param_3)
{
    const bool isArabic = (IsArabLanguage && IsArabLanguage());

    // Change this to your actual Arabic pack if different
    const char* path = isArabic
        ? "/Assets/tpp/pack/ui/ui_default_data2_ar.fpk"
        : "/Assets/tpp/pack/ui/ui_default_data2.fpk";

    FoxString s{};
    FoxStringCtor(&s, path);

    FoxPath tmp{};
    PathCInitWithString(&tmp, &s, param_3);

    if (s.Capacity > 0xF && s.Data.heapPtr)
        StdFree(s.Data.heapPtr, 0);

    // mirror reset (optional)
    s.Capacity = 0xF;
    s.Length = 0;
    s.Data.sso[0] = '\0';

    auto* outPath = reinterpret_cast<FoxPath*>(param_3);
    if (outPath->q[0] == 0)
        PathAssign(outPath, &tmp);

    LoadPageBlock(param_1, param_2, param_3);

    PathDtor(&tmp);

    #if DESTROY_PARAM3
    PathDtor(outPath);
    #endif
}

// ----------------------------------------
// Install hook
// ----------------------------------------
bool Install_UnkLoadUIDefaultDataFunc_Hook()
{
    const uintptr_t base = GetExeBase();
    if (!base)
        return false;

    // Resolve
    IsArabLanguage = reinterpret_cast<IsArabLanguage_t>(base + ToRva(ABS_IsArabLanguage));
    FoxStringCtor = reinterpret_cast<FoxStringCtor_t>(base + ToRva(ABS_FoxStringCtor));
    StdFree = reinterpret_cast<StdFree_t>(base + ToRva(ABS_StdFree));
    PathCInitWithString = reinterpret_cast<PathCInitWithString_t>(base + ToRva(ABS_PathCInit));
    PathAssign = reinterpret_cast<PathAssign_t>(base + ToRva(ABS_PathAssign));
    PathDtor = reinterpret_cast<PathDtor_t>(base + ToRva(ABS_PathDtor));
    LoadPageBlock = reinterpret_cast<LoadPageBlock_t>(base + ToRva(ABS_LoadPageBlock));

    void* target = reinterpret_cast<void*>(base + ToRva(ABS_UnkLoadFunc));

    // IMPORTANT: tolerate "already initialized" because dllmain.cpp calls MH_Initialize()
    const MH_STATUS initSt = MH_Initialize();
    if (initSt != MH_OK && initSt != MH_ERROR_ALREADY_INITIALIZED)
        return false;

    // Create hook (tolerate already created)
    MH_STATUS st = MH_CreateHook(target, &hkUnkLoadUIDefaultDataFunc, reinterpret_cast<void**>(&g_Orig));
    if (st != MH_OK && st != MH_ERROR_ALREADY_CREATED)
        return false;

    // Enable hook (tolerate already enabled)
    st = MH_EnableHook(target);
    if (st != MH_OK && st != MH_ERROR_ENABLED)
        return false;

    return true;
}