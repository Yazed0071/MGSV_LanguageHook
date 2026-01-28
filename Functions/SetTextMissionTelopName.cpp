#include "pch.h"
#include "SetTextMissionTelopName.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>

// -------------------------
// Config (IDA VA)
// CALL fox::snprintf at: 145D05D19
// In TelopStartTitleEvCall::SetTextMissionTelopName
// -------------------------
static constexpr uintptr_t IMAGE_BASE = 0x140000000ULL;
static constexpr uintptr_t CALLSITE_VA = 0x145D05D19ULL; // <- your screenshot: CALL fox::snprintf
static constexpr uintptr_t REL32_RANGE = 0x70000000ULL;  // ~1.75GB safety window

static uintptr_t gGameBase = 0;
static uintptr_t gCallSite = 0;
static uintptr_t gOrigTarget = 0;

static uint8_t   gOrigBytes[5] = {};
static void* gThunkMem = nullptr;

using FoxSnprintf_t = int(__cdecl*)(char* dst, size_t dstSize, const char* fmt, ...);
static FoxSnprintf_t gFoxSnprintf = nullptr;

// New format (swap)
static const char kFmt_D_S[] = "%d %s";

// VA -> RVA helper
static inline uintptr_t VA_to_RVA(uintptr_t va) {
    return va - IMAGE_BASE;
}

// resolve E8 rel32 target
static uintptr_t ResolveRelCallTarget(uintptr_t callSite /* address of E8 */) {
    if (*(uint8_t*)callSite != 0xE8) return 0;
    int32_t rel = *(int32_t*)(callSite + 1);
    return callSite + 5 + (intptr_t)rel;
}

static bool WriteMemory(void* dst, const void* src, size_t len) {
    DWORD oldProt = 0;
    if (!VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    std::memcpy(dst, src, len);
    FlushInstructionCache(GetCurrentProcess(), dst, len);
    VirtualProtect(dst, len, oldProt, &oldProt);
    return true;
}

static void* AllocNear(uintptr_t nearTo, size_t size) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    const size_t gran = si.dwAllocationGranularity; // usually 64KB
    const uintptr_t minAddr = (nearTo > REL32_RANGE) ? (nearTo - REL32_RANGE) : 0;
    const uintptr_t maxAddr = nearTo + REL32_RANGE;

    // Align down to allocation granularity
    uintptr_t start = nearTo & ~(uintptr_t)(gran - 1);

    // Scan downward then upward in granularity steps
    auto tryAllocAt = [&](uintptr_t addr) -> void* {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) return nullptr;
        if (mbi.State != MEM_FREE) return nullptr;

        // Ensure requested size fits in this free region
        uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
        size_t regionSize = mbi.RegionSize;
        if (addr < regionBase) return nullptr;
        size_t offset = (size_t)(addr - regionBase);
        if (offset + size > regionSize) return nullptr;

        return VirtualAlloc((void*)addr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        };

    for (uintptr_t addr = start; addr >= minAddr; ) {
        void* p = tryAllocAt(addr);
        if (p) return p;
        if (addr < gran) break;
        addr -= gran;
    }

    for (uintptr_t addr = start + gran; addr <= maxAddr; ) {
        void* p = tryAllocAt(addr);
        if (p) return p;
        if (addr > maxAddr - gran) break;
        addr += gran;
    }

    return nullptr;
}

// Thunk is called by the patched CALL. It jumps to our wrapper using absolute jump.
// CALL pushes return address -> wrapper returns straight back to game.
static int __cdecl EpisodeSnprintf_Wrapper(char* dst, size_t dstSize, const char* /*fmt*/, const char* episodeText, int episodeNum) {
    if (!gFoxSnprintf) return 0;
    // Swap: "%d %s" -> episodeNum then episodeText
    return gFoxSnprintf(dst, dstSize, kFmt_D_S, episodeNum, episodeText);
}

static bool PatchCallToThunk(uintptr_t callSite, uintptr_t thunkAddr) {
    // E8 rel32
    int64_t rel64 = (int64_t)thunkAddr - (int64_t)(callSite + 5);
    if (rel64 < INT32_MIN || rel64 > INT32_MAX) return false;

    uint8_t patch[5];
    patch[0] = 0xE8;
    *(int32_t*)&patch[1] = (int32_t)rel64;

    return WriteMemory((void*)callSite, patch, sizeof(patch));
}

bool Install_EpisodeFormatSwap(HMODULE hGame) {
    if (!hGame) return false;
    if (gThunkMem) return true; // already installed

    gGameBase = (uintptr_t)hGame;
    gCallSite = gGameBase + VA_to_RVA(CALLSITE_VA);

    // Validate original instruction is CALL rel32
    if (*(uint8_t*)gCallSite != 0xE8) {
        return false;
    }

    // Save original 5 bytes
    std::memcpy(gOrigBytes, (void*)gCallSite, sizeof(gOrigBytes));

    // Resolve original target (fox::snprintf)
    gOrigTarget = ResolveRelCallTarget(gCallSite);
    if (!gOrigTarget) return false;
    gFoxSnprintf = (FoxSnprintf_t)gOrigTarget;

    // Allocate near thunk
    gThunkMem = AllocNear(gCallSite, 0x1000);
    if (!gThunkMem) {
        // restore just in case
        WriteMemory((void*)gCallSite, gOrigBytes, sizeof(gOrigBytes));
        return false;
    }

    // Write thunk:
    //   mov rax, <EpisodeSnprintf_Wrapper>
    //   jmp rax
    uint8_t thunk[12];
    thunk[0] = 0x48; thunk[1] = 0xB8;                          // mov rax, imm64
    *(uint64_t*)&thunk[2] = (uint64_t)&EpisodeSnprintf_Wrapper; // imm64
    thunk[10] = 0xFF; thunk[11] = 0xE0;                        // jmp rax

    if (!WriteMemory(gThunkMem, thunk, sizeof(thunk))) {
        VirtualFree(gThunkMem, 0, MEM_RELEASE);
        gThunkMem = nullptr;
        WriteMemory((void*)gCallSite, gOrigBytes, sizeof(gOrigBytes));
        return false;
    }

    // Patch CALL to thunk
    if (!PatchCallToThunk(gCallSite, (uintptr_t)gThunkMem)) {
        VirtualFree(gThunkMem, 0, MEM_RELEASE);
        gThunkMem = nullptr;
        WriteMemory((void*)gCallSite, gOrigBytes, sizeof(gOrigBytes));
        return false;
    }

    return true;
}

void Remove_EpisodeFormatSwap() {
    if (!gCallSite) return;

    // Restore original bytes
    WriteMemory((void*)gCallSite, gOrigBytes, sizeof(gOrigBytes));

    if (gThunkMem) {
        VirtualFree(gThunkMem, 0, MEM_RELEASE);
        gThunkMem = nullptr;
    }

    gFoxSnprintf = nullptr;
    gOrigTarget = 0;
    gCallSite = 0;
    gGameBase = 0;
    std::memset(gOrigBytes, 0, sizeof(gOrigBytes));
}