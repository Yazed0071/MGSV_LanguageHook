#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <intrin.h>
#include "MinHook.h"

// --- IDA addresses (VA) ---
static constexpr uintptr_t kImageBase = 0x140000000ULL;
static constexpr uintptr_t kReloadForLangChange_VA = 0x14092E330ULL; // function start (your listing)

// --- Runtime base ---
static uintptr_t gBase = 0;

// Return is in AL (0/1). Treat as bool.
using ReloadForLangChange_t = bool(__fastcall*)(void* uiDependThis, void* uiCommonDataMgr, int langId);
static ReloadForLangChange_t gOrig_ReloadForLangChange = nullptr;

static inline uintptr_t VA_to_RVA(uintptr_t va) { return va - kImageBase; }

static void DebugPrint(const char* fmt, ...)
{
    char buf[1024];
    va_list va;
    va_start(va, fmt);
    vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, va);
    va_end(va);
    OutputDebugStringA(buf);
}

static bool __fastcall Hook_ReloadForLangChange(void* self, void* mgr, int langId)
{
    // step is *(int*)(this + 0x84)
    const int step = *(int*)((uint8_t*)self + 0x84);
    void* caller = _ReturnAddress();

    // Optional spam filter: only print when (step/langId) changes
    static int sLastStep = -1;
    static int sLastLang = -1;
    if (step != sLastStep || langId != sLastLang)
    {
        DebugPrint("[ReloadForLangChange] this=%p mgr=%p langId=%d step=%d caller=%p\n",
            self, mgr, langId, step, caller);
        sLastStep = step;
        sLastLang = langId;
    }

    int patchedLang = langId;

    // Remap Japanese (8) -> Arabic (6)
    // Best point: step 9 is where ChangeLanguage(langId) happens.
    if (langId == 8 && step == 9)
    {
        patchedLang = 6;
        DebugPrint("[ReloadForLangChange] REMAP langId %d -> %d at step=%d\n", langId, patchedLang, step);
    }

    return gOrig_ReloadForLangChange(self, mgr, patchedLang);
}

bool Install_ReloadForLangChangeHook(HMODULE hGame)
{
    if (!hGame) return false;
    gBase = (uintptr_t)hGame;

    const uintptr_t target = gBase + VA_to_RVA(kReloadForLangChange_VA);

    // (Optional) sanity check first bytes match your IDA prologue:
    // 48 89 5C 24 10 55 56 57 48 83 EC 60 ...
    // You can read and log them here if you want.

    const auto init = MH_Initialize();
    if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
        return false;

    if (MH_CreateHook((LPVOID)target,
        (LPVOID)&Hook_ReloadForLangChange,
        (LPVOID*)&gOrig_ReloadForLangChange) != MH_OK)
        return false;

    if (MH_EnableHook((LPVOID)target) != MH_OK)
        return false;

    DebugPrint("[ReloadForLangChange] Hooked at %p\n", (void*)target);
    return true;
}

bool Uninstall_ReloadForLangChangeHook()
{
    if (!gBase) return true;

    const uintptr_t target = gBase + VA_to_RVA(kReloadForLangChange_VA);

    MH_DisableHook((LPVOID)target);
    MH_RemoveHook((LPVOID)target);

    gOrig_ReloadForLangChange = nullptr;
    gBase = 0;

    // If you have multiple hooks, don't MH_Uninitialize() here.
    return true;
}