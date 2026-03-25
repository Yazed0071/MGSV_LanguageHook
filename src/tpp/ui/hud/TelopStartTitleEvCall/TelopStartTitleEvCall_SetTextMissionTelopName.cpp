#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using FoxSnprintf_t = int(__cdecl*)(char* dst, size_t dstSize, const char* fmt, ...);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static FoxSnprintf_t gFoxSnprintf = nullptr;

    static uintptr_t gGameBase = 0;
    static uintptr_t gCallSite = 0;
    static uintptr_t gOrigTarget = 0;

    static uint8_t gOrigBytes[5] = {};
    static void* gThunkMem = nullptr;

    static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    static constexpr uintptr_t REL32_RANGE = 0x70000000ull;

    static const char kFmt_D_S[] = "%d %s";
}

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

static __forceinline bool IsArabicSafe()
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

static uintptr_t ResolveRelCallTarget(uintptr_t callSite)
{
    if (!callSite || *reinterpret_cast<uint8_t*>(callSite) != 0xE8)
        return 0;

    const int32_t rel = *reinterpret_cast<int32_t*>(callSite + 1);
    return callSite + 5 + static_cast<intptr_t>(rel);
}

static bool WriteMemory(void* dst, const void* src, size_t len)
{
    DWORD oldProt = 0;
    if (!VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;

    std::memcpy(dst, src, len);
    FlushInstructionCache(GetCurrentProcess(), dst, len);
    VirtualProtect(dst, len, oldProt, &oldProt);
    return true;
}

static void* AllocNear(uintptr_t nearTo, size_t size)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    const size_t gran = si.dwAllocationGranularity;
    const uintptr_t minAddr = (nearTo > REL32_RANGE) ? (nearTo - REL32_RANGE) : 0;
    const uintptr_t maxAddr = nearTo + REL32_RANGE;

    uintptr_t start = nearTo & ~(uintptr_t)(gran - 1);

    auto tryAllocAt = [&](uintptr_t addr) -> void*
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)))
                return nullptr;

            if (mbi.State != MEM_FREE)
                return nullptr;

            const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const size_t regionSize = mbi.RegionSize;

            if (addr < regionBase)
                return nullptr;

            const size_t offset = static_cast<size_t>(addr - regionBase);
            if (offset + size > regionSize)
                return nullptr;

            return VirtualAlloc(reinterpret_cast<void*>(addr), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        };

    for (uintptr_t addr = start; addr >= minAddr;)
    {
        void* p = tryAllocAt(addr);
        if (p)
            return p;

        if (addr < gran)
            break;

        addr -= gran;
    }

    for (uintptr_t addr = start + gran; addr <= maxAddr;)
    {
        void* p = tryAllocAt(addr);
        if (p)
            return p;

        if (addr > maxAddr - gran)
            break;

        addr += gran;
    }

    return nullptr;
}

static int __cdecl EpisodeSnprintf_Wrapper(char* dst, size_t dstSize, const char* fmt, const char* episodeText, int episodeNum)
{
    if (!gFoxSnprintf)
        return 0;

    if (!IsArabicSafe())
        return gFoxSnprintf(dst, dstSize, fmt, episodeText, episodeNum);

    return gFoxSnprintf(dst, dstSize, kFmt_D_S, episodeNum, episodeText);
}

static bool PatchCallToThunk(uintptr_t callSite, uintptr_t thunkAddr)
{
    const int64_t rel64 = static_cast<int64_t>(thunkAddr) - static_cast<int64_t>(callSite + 5);
    if (rel64 < INT32_MIN || rel64 > INT32_MAX)
        return false;

    uint8_t patch[5]{};
    patch[0] = 0xE8;
    *reinterpret_cast<int32_t*>(&patch[1]) = static_cast<int32_t>(rel64);

    return WriteMemory(reinterpret_cast<void*>(callSite), patch, sizeof(patch));
}

bool InstallSetTextMissionTelopNameArabicEpisodeFormatHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (gThunkMem)
        return true;

    gGameBase = reinterpret_cast<uintptr_t>(hGame);

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gCallSite =
        ToRuntimeVA(hGame, gAddr.SetTextMissionTelopNameEpisodeSnprintfCall);

    if (!gIsArabLanguage || !gCallSite)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::SetTextMissionTelopName] Resolve failed.\n");
        return false;
    }

    if (*reinterpret_cast<uint8_t*>(gCallSite) != 0xE8)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::SetTextMissionTelopName] Callsite is not E8.\n");
        return false;
    }

    std::memcpy(gOrigBytes, reinterpret_cast<void*>(gCallSite), sizeof(gOrigBytes));

    gOrigTarget = ResolveRelCallTarget(gCallSite);
    if (!gOrigTarget)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::SetTextMissionTelopName] ResolveRelCallTarget failed.\n");
        return false;
    }

    gFoxSnprintf = reinterpret_cast<FoxSnprintf_t>(gOrigTarget);

    gThunkMem = AllocNear(gCallSite, 0x1000);
    if (!gThunkMem)
    {
        WriteMemory(reinterpret_cast<void*>(gCallSite), gOrigBytes, sizeof(gOrigBytes));
        Log("[tpp::ui::hud::TelopStartTitleEvCall::SetTextMissionTelopName] AllocNear failed.\n");
        return false;
    }

    uint8_t thunk[12]{};
    thunk[0] = 0x48;
    thunk[1] = 0xB8;
    *reinterpret_cast<uint64_t*>(&thunk[2]) = reinterpret_cast<uint64_t>(&EpisodeSnprintf_Wrapper);
    thunk[10] = 0xFF;
    thunk[11] = 0xE0;

    if (!WriteMemory(gThunkMem, thunk, sizeof(thunk)))
    {
        VirtualFree(gThunkMem, 0, MEM_RELEASE);
        gThunkMem = nullptr;
        WriteMemory(reinterpret_cast<void*>(gCallSite), gOrigBytes, sizeof(gOrigBytes));
        Log("[tpp::ui::hud::TelopStartTitleEvCall::SetTextMissionTelopName] Write thunk failed.\n");
        return false;
    }

    if (!PatchCallToThunk(gCallSite, reinterpret_cast<uintptr_t>(gThunkMem)))
    {
        VirtualFree(gThunkMem, 0, MEM_RELEASE);
        gThunkMem = nullptr;
        WriteMemory(reinterpret_cast<void*>(gCallSite), gOrigBytes, sizeof(gOrigBytes));
        Log("[tpp::ui::hud::TelopStartTitleEvCall::SetTextMissionTelopName] Patch call failed.\n");
        return false;
    }

    Log("[tpp::ui::hud::TelopStartTitleEvCall::SetTextMissionTelopName] Arabic episode format hook enabled.\n");
    return true;
}

void RemoveSetTextMissionTelopNameArabicEpisodeFormatHook()
{
    if (gCallSite)
        WriteMemory(reinterpret_cast<void*>(gCallSite), gOrigBytes, sizeof(gOrigBytes));

    if (gThunkMem)
    {
        VirtualFree(gThunkMem, 0, MEM_RELEASE);
        gThunkMem = nullptr;
    }

    gFoxSnprintf = nullptr;
    gOrigTarget = 0;
    gCallSite = 0;
    gGameBase = 0;
    std::memset(gOrigBytes, 0, sizeof(gOrigBytes));

    Log("[tpp::ui::hud::TelopStartTitleEvCall::SetTextMissionTelopName] Arabic episode format hook removed.\n");
}