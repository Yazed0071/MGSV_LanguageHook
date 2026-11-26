#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "log.h"
#include "AddressSet.h"

namespace
{
    using LocatePath_t = bool(__fastcall*)(const void* fsPath, uint32_t flags);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr uint64_t CODE_MASK = 0x0007FFFFFFFFFFFFull;
    constexpr uint64_t EXT_FPKD = 0xED50000000000000ull;
    constexpr uint64_t EXT_PFTXS = 0xB2F8000000000000ull;
    constexpr int CACHE_SIZE = 64;

    const uint8_t kPrologue[] = { 0x48, 0x8B, 0xC4, 0x55, 0x57, 0x41, 0x56, 0x48,
                                  0x8D, 0x68, 0xA1, 0x48, 0x81, 0xEC, 0xA0, 0x00 };

    LocatePath_t gLocatePath = nullptr;
    std::atomic<uint64_t> gFound[CACHE_SIZE] = {};
    std::atomic<int> gFoundNext{ 0 };

    bool CodeMatches(const void* target, const uint8_t* expected, size_t size)
    {
        __try
        {
            return std::memcmp(target, expected, size) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool IsCachedFound(uint64_t code)
    {
        for (const auto& entry : gFound)
        {
            if (entry.load(std::memory_order_relaxed) == code)
                return true;
        }
        return false;
    }

    void RememberFound(uint64_t code)
    {
        const int slot = gFoundNext.fetch_add(1) % CACHE_SIZE;
        gFound[slot].store(code, std::memory_order_relaxed);
    }

    bool Locate(uint64_t code)
    {
        alignas(16) uint8_t fsPath[64] = {};
        std::memcpy(fsPath, &code, sizeof(code));
        __try
        {
            return gLocatePath(fsPath, 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
}

bool InitFoxAssetExists(HMODULE hGame)
{
    if (gLocatePath)
        return true;
    if (!hGame || !gAddr.FsLocatePath)
    {
        Log("[FileLocationManager::LocatePath] address missing - Arabic files are assumed present.\n");
        return false;
    }
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (gAddr.FsLocatePath - IDA_IMAGE_BASE));
    if (!CodeMatches(target, kPrologue, sizeof(kPrologue)))
    {
        Log("[FileLocationManager::LocatePath] prologue mismatch at %p - Arabic files are assumed present.\n", target);
        return false;
    }
    gLocatePath = reinterpret_cast<LocatePath_t>(target);
    Log("[FileLocationManager::LocatePath] file existence check ready at %p.\n", target);
    return true;
}

bool FoxAssetExists(uint64_t code)
{
    if (!code)
        return false;
    if (!gLocatePath)
        return true;
    if (IsCachedFound(code))
        return true;
    if (!Locate(code))
        return false;
    RememberFound(code);
    return true;
}

bool FoxPackExists(uint64_t fpkCode, bool withTextures)
{
    if (!FoxAssetExists(fpkCode))
        return false;
    if (!FoxAssetExists((fpkCode & CODE_MASK) | EXT_FPKD))
        return false;
    if (withTextures && !FoxAssetExists((fpkCode & CODE_MASK) | EXT_PFTXS))
        return false;
    return true;
}
