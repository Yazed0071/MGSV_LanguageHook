#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <atomic>
#include <intrin.h>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using GetUTF8TextFromBack_t = uint64_t(__fastcall*)(char* dst, int dstSize, const uint8_t* src, int count);

    GetUTF8TextFromBack_t gOrigGetUTF8TextFromBack = nullptr;
    void* gTarget = nullptr;
    uintptr_t gTelopRetA = 0;
    uintptr_t gTelopRetB = 0;

    std::atomic<int> gLogBudget{ 4 };

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

    uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
    {
        return absVa ? reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE) : 0;
    }

    bool IsDirectCallTo(uintptr_t returnAddress, uintptr_t target)
    {
        __try
        {
            const auto site = reinterpret_cast<const uint8_t*>(returnAddress - 5);
            if (site[0] != 0xE8)
                return false;
            const int32_t rel = *reinterpret_cast<const int32_t*>(site + 1);
            return returnAddress + static_cast<intptr_t>(rel) == target;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    int CountUtf8Chars(const uint8_t* s)
    {
        int count = 0;
        __try
        {
            while (*s)
            {
                const uint8_t b = *s;
                int len = 1;
                if (b & 0x80)
                {
                    if ((b & 0xE0) == 0xC0) len = 2;
                    else if ((b & 0xF0) == 0xE0) len = 3;
                    else if ((b & 0xF8) == 0xF0) len = 4;
                    else if ((b & 0xFC) == 0xF8) len = 5;
                    else if ((b & 0xFE) == 0xFC) len = 6;
                    else return 0;
                }
                s += len;
                ++count;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return -1;
        }
        return count;
    }

    uint64_t __fastcall hkGetUTF8TextFromBack(char* dst, int dstSize, const uint8_t* src, int count)
    {
        if (!src)
            return gOrigGetUTF8TextFromBack(dst, dstSize, src, count);

        const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
        const bool telop = ret && (ret == gTelopRetA || ret == gTelopRetB);
        const int requested = count;

        if (telop)
            ++count;

        const int total = CountUtf8Chars(src);
        if (total >= 0 && count > total)
            count = total;

        if (count != requested && count == total && gLogBudget.load() > 0)
        {
            gLogBudget.fetch_sub(1);
            Log("[GetUTF8TextFromBack] %s: %d -> %d chars\n",
                requested < total ? "telop caption completed" : "reveal clamped", requested, count);
        }

        return gOrigGetUTF8TextFromBack(dst, dstSize, src, count);
    }
}

bool InstallGetUTF8TextFromBackArabicRevealHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.GetUTF8TextFromBack)
    {
        Log("[GetUTF8TextFromBack] Missing address.\n");
        return false;
    }

    const uintptr_t target = ToRuntimeVA(hGame, gAddr.GetUTF8TextFromBack);
    const uintptr_t retA = ToRuntimeVA(hGame, gAddr.TelopStartTitleFromBackRetA);
    const uintptr_t retB = ToRuntimeVA(hGame, gAddr.TelopStartTitleFromBackRetB);
    gTelopRetA = (retA && IsDirectCallTo(retA, target)) ? retA : 0;
    gTelopRetB = (retB && IsDirectCallTo(retB, target)) ? retB : 0;
    if (!gTelopRetA || !gTelopRetB)
        Log("[GetUTF8TextFromBack] Telop call sites did not verify (A=%d B=%d).\n",
            gTelopRetA != 0, gTelopRetB != 0);

    gTarget = reinterpret_cast<void*>(target);
    if (MH_CreateHook(gTarget, &hkGetUTF8TextFromBack, reinterpret_cast<LPVOID*>(&gOrigGetUTF8TextFromBack)) != MH_OK ||
        MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[GetUTF8TextFromBack] Hook install failed.\n");
        gTarget = nullptr;
        return false;
    }

    Log("[GetUTF8TextFromBack] Arabic reveal fix enabled.\n");
    return true;
}

void RemoveGetUTF8TextFromBackArabicRevealHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigGetUTF8TextFromBack = nullptr;
}
