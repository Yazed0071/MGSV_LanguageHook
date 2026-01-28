#include "pch.h"

#include "FUN_145cc6360.h"
#include "log.h"
#include "MinHook.h"
#include <windows.h>
#include <cstdint>
#include <vector>

// Offset of function to hook (from mgsvtpp.exe base)
#define FUNCTION_OFFSET 0x5CC6360

// -------------------- Language Entry Structure --------------------
struct LanguageEntry {
    uint64_t key;
    uint64_t value;
    const char* name;
};

static std::vector<LanguageEntry> g_LanguagesToAdd = {
    { 6,  0x00FB22736BF48BULL, "Arabic" },  // Arabic language entry
};

// -------------------- Globals --------------------
static void* g_TargetAddress = nullptr;
typedef void(__fastcall* fnOriginal_t)(void*);
static fnOriginal_t g_fpOriginal = nullptr;

// -------------------- Helpers --------------------
inline uint8_t GetEnabled(void* obj) { return *(uint8_t*)((uintptr_t)obj + 0xC0); }
inline int32_t GetStoredCount(void* obj) { return *(int32_t*)((uintptr_t)obj + 0x108); }
inline void SetStoredCount(void* obj, int32_t val) { *(int32_t*)((uintptr_t)obj + 0x108) = val; }
inline uint64_t* GetTableEntry(void* obj, int index) { return (uint64_t*)((uintptr_t)obj + 0x1370 + (index * 0x10)); }

// -------------------- Hook Function --------------------
void __fastcall Detour_TargetInit(void* param_1)
{
    Log("[LangHook] Called\n");

    if (g_fpOriginal)
        g_fpOriginal(param_1);
    else {
        Log("[LangHook] ERROR: Original function pointer is NULL\n");
        return;
    }

    if (!GetEnabled(param_1)) {
        Log("[LangHook] Object not enabled, skipping\n");
        return;
    }

    int32_t count = GetStoredCount(param_1);
    int32_t numToAdd = (int32_t)g_LanguagesToAdd.size();

    Log("[LangHook] Stored count=%d, adding %d\n", count, numToAdd);

    if (count < 0 || count + numToAdd >= 256) {
        Log("[LangHook] Invalid count, aborting\n");
        return;
    }

    for (int i = 0; i < numToAdd; i++) {
        uint64_t* entry = GetTableEntry(param_1, count + i);
        entry[0] = g_LanguagesToAdd[i].key;
        entry[1] = g_LanguagesToAdd[i].value;

        Log("[LangHook] Added %s (key=%llu, value=0x%llX)\n",
            g_LanguagesToAdd[i].name, g_LanguagesToAdd[i].key, g_LanguagesToAdd[i].value);
    }

    SetStoredCount(param_1, count + numToAdd);
    Log("[LangHook] New count=%d\n", count + numToAdd);
}

// -------------------- Hook Management --------------------
bool InstallLanguageHook(HMODULE hGame)
{
    if (!hGame)
        hGame = GetModuleHandleA("mgsvtpp.exe");

    g_TargetAddress = (void*)((uintptr_t)hGame + FUNCTION_OFFSET);

    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(g_TargetAddress, &mbi, sizeof(mbi));

    Log("[LangHook] Game base: %p  Target RVA: 0x%X  Target VA: %p\n", hGame, FUNCTION_OFFSET, g_TargetAddress);
    Log("[LangHook] VirtualQuery: Protect=0x%X State=0x%X Type=0x%X\n", mbi.Protect, mbi.State, mbi.Type);

    MH_STATUS status = MH_CreateHook(g_TargetAddress, &Detour_TargetInit, reinterpret_cast<LPVOID*>(&g_fpOriginal));
    if (status != MH_OK) {
        Log("[LangHook] MH_CreateHook failed: %d\n", status);
        return false;
    }

    status = MH_EnableHook(g_TargetAddress);
    if (status != MH_OK) {
        Log("[LangHook] MH_EnableHook failed: %d\n", status);
        return false;
    }

    Log("[LangHook] Installed at %p (orig=%p)\n", g_TargetAddress, g_fpOriginal);
    return true;
}

void RemoveLanguageHook()
{
    if (g_TargetAddress) {
        MH_DisableHook(g_TargetAddress);
        MH_RemoveHook(g_TargetAddress);
    }
    Log("[LangHook] Removed\n");
}
