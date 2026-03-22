#include "log.h"
#include "MinHook.h"
#include <windows.h>
#include <cstdint>
#include <vector>
#include "AddressSet.h"

// Function: converts stored IDA absolute VA to runtime VA.
// Params:
// - hGame: game module base
// - absVa: absolute VA from AddressSet
// Returns:
// - runtime VA
static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

// -------------------- Language Entry Structure --------------------
struct LanguageEntry
{
    uint64_t key;
    uint64_t value;
    const char* name;
};

static std::vector<LanguageEntry> g_LanguagesToAdd = {
    { 6,  0x00FB22736BF48BULL, "Arabic"  },
    { 9,  0x007FF8A9A9E6A7ULL, "Chinese" },
    { 10, 0x00A886C2115A2DULL, "Korean"  },
};

// -------------------- Globals --------------------
static void* g_TargetAddress = nullptr;

// Function: original function type for FUN_145cc6360.
// Params:
// - param_1: language list object
using fnOriginal_t = void(__fastcall*)(void* param_1);

static fnOriginal_t g_fpOriginal = nullptr;

// -------------------- Helpers --------------------

// Function: reads enabled flag from the object.
// Params:
// - obj: language list object
// Returns:
// - enabled byte
inline uint8_t GetEnabled(void* obj)
{
    return *(uint8_t*)((uintptr_t)obj + 0xC0);
}

// Function: reads stored language count.
// Params:
// - obj: language list object
// Returns:
// - current stored count
inline int32_t GetStoredCount(void* obj)
{
    return *(int32_t*)((uintptr_t)obj + 0x108);
}

// Function: writes stored language count.
// Params:
// - obj: language list object
// - val: new count
inline void SetStoredCount(void* obj, int32_t val)
{
    *(int32_t*)((uintptr_t)obj + 0x108) = val;
}

// Function: returns pointer to one table entry.
// Params:
// - obj: language list object
// - index: table index
// Returns:
// - pointer to the entry
inline uint64_t* GetTableEntry(void* obj, int index)
{
    return (uint64_t*)((uintptr_t)obj + 0x1370 + (index * 0x10));
}

// -------------------- Hook Function --------------------

// Function: detour for FUN_145cc6360.
// Params:
// - param_1: language list object
void __fastcall Detour_TargetInit(void* param_1)
{
    Log("[LangHook] Called\n");

    if (!g_fpOriginal)
    {
        Log("[LangHook] ERROR: original function pointer is NULL\n");
        return;
    }

    g_fpOriginal(param_1);

    if (!GetEnabled(param_1))
    {
        Log("[LangHook] Object not enabled, skipping\n");
        return;
    }

    int32_t count = GetStoredCount(param_1);
    const int32_t numToAdd = static_cast<int32_t>(g_LanguagesToAdd.size());

    Log("[LangHook] Stored count=%d, adding %d\n", count, numToAdd);

    if (count < 0 || count + numToAdd >= 256)
    {
        Log("[LangHook] Invalid count, aborting\n");
        return;
    }

    for (int i = 0; i < numToAdd; ++i)
    {
        uint64_t* entry = GetTableEntry(param_1, count + i);
        entry[0] = g_LanguagesToAdd[i].key;
        entry[1] = g_LanguagesToAdd[i].value;

        Log("[LangHook] Added %s (key=%llu, value=0x%llX)\n",
            g_LanguagesToAdd[i].name,
            static_cast<unsigned long long>(g_LanguagesToAdd[i].key),
            static_cast<unsigned long long>(g_LanguagesToAdd[i].value));
    }

    SetStoredCount(param_1, count + numToAdd);
    Log("[LangHook] New count=%d\n", count + numToAdd);
}

// -------------------- Hook Management --------------------

// Function: installs the language-list hook.
// Params:
// - hGame: game module base
// Returns:
// - true on success
bool InstallLanguageHook(HMODULE hGame)
{
    if (!hGame)
        hGame = GetModuleHandleA("mgsvtpp.exe");

    if (!hGame)
        return false;

    if (gAddr.FixKorCh_Fun145cc6360 == 0)
    {
        Log("[LangHook] Missing address for FUN_145cc6360\n");
        return false;
    }

    g_TargetAddress =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.FixKorCh_Fun145cc6360));

    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(g_TargetAddress, &mbi, sizeof(mbi));

    Log("[LangHook] Game base: %p  Target ABS: 0x%llX  Target VA: %p\n",
        hGame,
        static_cast<unsigned long long>(gAddr.FixKorCh_Fun145cc6360),
        g_TargetAddress);

    Log("[LangHook] VirtualQuery: Protect=0x%X State=0x%X Type=0x%X\n",
        mbi.Protect, mbi.State, mbi.Type);

    MH_STATUS status =
        MH_CreateHook(
            g_TargetAddress,
            reinterpret_cast<void*>(&Detour_TargetInit),
            reinterpret_cast<LPVOID*>(&g_fpOriginal));

    if (status != MH_OK)
    {
        Log("[LangHook] MH_CreateHook failed: %d\n", static_cast<int>(status));
        return false;
    }

    status = MH_EnableHook(g_TargetAddress);
    if (status != MH_OK)
    {
        Log("[LangHook] MH_EnableHook failed: %d\n", static_cast<int>(status));
        return false;
    }

    Log("[LangHook] Installed at %p (orig=%p)\n", g_TargetAddress, g_fpOriginal);
    return true;
}

// Function: removes the language-list hook.
// Params:
// - none
void RemoveLanguageHook()
{
    if (g_TargetAddress)
    {
        MH_DisableHook(g_TargetAddress);
        MH_RemoveHook(g_TargetAddress);
        g_TargetAddress = nullptr;
    }

    g_fpOriginal = nullptr;
    Log("[LangHook] Removed\n");
}