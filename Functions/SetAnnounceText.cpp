#include "pch.h"
#include "SetAnnounceText.h"

#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include "MinHook.h"

// -----------------------------
// Addresses from your listing
// -----------------------------
// Function entry (your disasm shows SetAnnounceText body at 0x14A3EAE70)
static constexpr uintptr_t kSetAnnounceText_VA = 0x14A3EAE70ULL;

// Inside SetAnnounceText: CALL fox::GetQuarkSystemTable at 0x14A3EAE8F (E8 rel32)
static constexpr uintptr_t kGetQuarkCallsite_VA = 0x14A3EAE8FULL;

// Image base assumption (MGSV typical)
static constexpr uintptr_t kImageBase = 0x140000000ULL;

static uintptr_t gBase = 0;

// -----------------------------
// Helpers
// -----------------------------
static uintptr_t VA_to_RVA(uintptr_t va) {
    return va - kImageBase;
}

static uintptr_t ResolveRelCallTarget(uintptr_t callSite /* address of E8 xx xx xx xx */) {
    if (*(uint8_t*)callSite != 0xE8) return 0;
    int32_t rel = *(int32_t*)(callSite + 1);
    return callSite + 5 + (intptr_t)rel;
}

// fox::GetQuarkSystemTable() -> returns QuarkSystemTable*
using GetQuarkSystemTable_t = void* (__fastcall*)();

static GetQuarkSystemTable_t gGetQuarkSystemTable = nullptr;

// Original SetAnnounceText
using SetAnnounceText_t = void(__fastcall*)(void* thisPtr, uint32_t count);
static SetAnnounceText_t gOrig_SetAnnounceText = nullptr;

// Vtable calls used inside SetAnnounceText (based on your pseudo/disasm)
using VCall_750_t = const char* (__fastcall*)(void* self, uint64_t arg);                     // [vtable + 0x750]
using VFormat_18_t = void(__fastcall*)(void* self, void* outBuf, int size, const char* fmt, ...); // [vtable + 0x18]
using VCall_308_t = void(__fastcall*)(void* self, uint64_t h, float a, float b, float c);        // [vtable + 0x308]
using VCall_708_t = void(__fastcall*)(void* self, uint64_t a, uint64_t b, void* text, int one);  // [vtable + 0x708]

// -----------------------------
// Our replacement
// -----------------------------
static void __fastcall Hook_SetAnnounceText(void* thisPtr, uint32_t count) {
    // If anything looks off, fall back to original.
    if (!thisPtr || !gGetQuarkSystemTable || !gOrig_SetAnnounceText) {
        if (gOrig_SetAnnounceText) gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    void* quark = gGetQuarkSystemTable();
    if (!quark) {
        gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    // plVar1 = *(qword*)(quark + 0x20)
    void* fmtObj = *(void**)((uint8_t*)quark + 0x20);
    if (!fmtObj) {
        gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    // plVar2 = *(qword*)(*(qword*)(this + 0x40) + 0x20)
    uint64_t uiOwner = *(uint64_t*)((uint8_t*)thisPtr + 0x40);
    if (!uiOwner) {
        gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    void* uiObj = *(void**)((uint8_t*)uiOwner + 0x20);
    if (!uiObj) {
        gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    // uVar5 = uiObj->vfunc_750(uiObj, *(qword*)(this + 0x98))
    void** uiVt = *(void***)uiObj;
    if (!uiVt) {
        gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    auto fn750 = (VCall_750_t)uiVt[0x750 / 8];
    if (!fn750) {
        gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    uint64_t arg98 = *(uint64_t*)((uint8_t*)thisPtr + 0x98);
    const char* name = fn750(uiObj, arg98);

    // fmtObj->vfunc_18(fmtObj, this+0xA0, 300, "%d %s", count, name)
    void** fmtVt = *(void***)fmtObj;
    if (!fmtVt) {
        gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    auto fnFmt = (VFormat_18_t)fmtVt[0x18 / 8];
    if (!fnFmt) {
        gOrig_SetAnnounceText(thisPtr, count);
        return;
    }

    void* outBuf = (void*)((uint8_t*)thisPtr + 0xA0);
    fnFmt(fmtObj, outBuf, 300, "%d %s", (int)count, (name ? name : ""));

    // Remaining logic identical to your function:
    // if *(char*)(this+0x8C)==0 then (fVar7=0.6, fVar8=1.0, uVar6=0.1) else (fVar7=1.0, fVar8=0.2, uVar6=0)
    float fVar7, fVar8, fVar6;
    if (*(uint8_t*)((uint8_t*)thisPtr + 0x8C) == 0) {
        fVar7 = 0.6f;
        fVar8 = 1.0f;
        fVar6 = 0.1f; // 0x3DCCCCCD
    }
    else {
        fVar7 = 1.0f;
        fVar8 = 0.2f;
        fVar6 = 0.0f;
    }

    // uiObj->vfunc_308(uiObj, *(qword*)(this+0x58), fVar7, fVar8, fVar6)
    auto fn308 = (VCall_308_t)uiVt[0x308 / 8];
    if (fn308) {
        uint64_t h58 = *(uint64_t*)((uint8_t*)thisPtr + 0x58);
        fn308(uiObj, h58, fVar7, fVar8, fVar6);
    }

    // uiObj->vfunc_708(uiObj, *(qword*)(this+0x60), *(qword*)(this+0x38), this+0xA0, 1)
    auto fn708 = (VCall_708_t)uiVt[0x708 / 8];
    if (fn708) {
        uint64_t a60 = *(uint64_t*)((uint8_t*)thisPtr + 0x60);
        uint64_t a38 = *(uint64_t*)((uint8_t*)thisPtr + 0x38);
        fn708(uiObj, a60, a38, outBuf, 1);

        // second call uses *(qword*)(this+0x68)
        uint64_t a68 = *(uint64_t*)((uint8_t*)thisPtr + 0x68);
        fn708(uiObj, a68, a38, outBuf, 1);
    }

    // done (we fully replaced the original function)
}

// -----------------------------
// Install / Uninstall
// -----------------------------
bool Install_CountAnnounceSwap_Hook(HMODULE hGame) {
    if (!hGame) return false;

    gBase = (uintptr_t)hGame;

    // Resolve fox::GetQuarkSystemTable from the callsite inside SetAnnounceText
    uintptr_t getQuarkCallsite = gBase + VA_to_RVA(kGetQuarkCallsite_VA);
    uintptr_t getQuarkAddr = ResolveRelCallTarget(getQuarkCallsite);
    if (!getQuarkAddr) return false;

    gGetQuarkSystemTable = (GetQuarkSystemTable_t)getQuarkAddr;

    // Hook SetAnnounceText
    uintptr_t setAnnounceAddr = gBase + VA_to_RVA(kSetAnnounceText_VA);

    if (MH_CreateHook((LPVOID)setAnnounceAddr,
        (LPVOID)&Hook_SetAnnounceText,
        (LPVOID*)&gOrig_SetAnnounceText) != MH_OK) {
        return false;
    }

    if (MH_EnableHook((LPVOID)setAnnounceAddr) != MH_OK) {
        return false;
    }

    return true;
}

bool Uninstall_CountAnnounceSwap_Hook() {
    if (!gBase) return true;

    uintptr_t setAnnounceAddr = gBase + VA_to_RVA(kSetAnnounceText_VA);

    MH_DisableHook((LPVOID)setAnnounceAddr);
    MH_RemoveHook((LPVOID)setAnnounceAddr);

    gOrig_SetAnnounceText = nullptr;
    gGetQuarkSystemTable = nullptr;
    gBase = 0;

    return true;
}