#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using Ctor_t = void*(__fastcall*)(void* collector);
    using CreateMemArray_t = void(__fastcall*)(void* collector, uint8_t type, size_t size, uint16_t count,
                                                uint32_t tag);
    using Alloc_t = void*(__fastcall*)(size_t size, uint32_t tag);
    using Free_t = void(__fastcall*)(void* p, uint32_t tag);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr uint32_t STOCK_LINE_SIZE = 0x20CC;
    constexpr double STOCK_LINE_LIMIT = 8396.8;
    constexpr uint32_t LINE_SIZE = 0x10500;
    constexpr uint8_t LINE_TYPE = 2;
    constexpr uint16_t LINE_COUNT = 2;
    constexpr uint32_t LINE_TAG = 0x120008;
    constexpr size_t COL_GROUP_COUNT = 0x38;
    constexpr size_t COL_GROUPS = 0x40;
    constexpr size_t GROUP_STRIDE = 0x10;
    constexpr size_t GROUP_SLOTS = 0x08;
    constexpr size_t SLOT_STRIDE = 0x28;
    constexpr size_t SLOT_STATE = 0x08;
    constexpr size_t SLOT_BUFFER = 0x10;

    static_assert(LINE_SIZE >= 12 + 255 * 4 + 0xFFFF, "a line can hold the largest entry the subp format allows");
    static_assert(LINE_SIZE % 16 == 0, "line buffers stay 16-byte aligned");

    const uint8_t kCtorPrologue[] = { 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57 };
    const uint8_t kAllocOpcode[] = { 0x41, 0xB8 };
    const uint8_t kReadOpcode[] = { 0x41, 0xBC };
    const uint8_t kAllocPrologue[] = { 0x44, 0x8B, 0xC2, 0xBA, 0x10, 0x00, 0x00, 0x00, 0xE9 };
    const uint8_t kFreePrologue[] = { 0x48, 0x85, 0xC9, 0x74, 0x0A, 0x44, 0x8B, 0xC2, 0x33, 0xD2, 0xE9 };
    const uint8_t kCreateMemArrayThunk[] = { 0xE9 };

    Ctor_t oCtor = nullptr;
    CreateMemArray_t gCreateMemArray = nullptr;
    Alloc_t gAlloc = nullptr;
    Free_t gFree = nullptr;
    void** gInstance = nullptr;
    uint8_t* gAllocSize = nullptr;
    uint8_t* gReadSize = nullptr;
    double* gLimit = nullptr;
    void* gCtorTarget = nullptr;
    volatile LONG gResized = 0;

    bool CodeMatches(const void* target, const void* expected, size_t size)
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

    bool WriteBytes(void* target, const void* bytes, size_t size)
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;
        std::memcpy(target, bytes, size);
        DWORD ignored = 0;
        VirtualProtect(target, size, oldProtect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), target, size);
        return true;
    }

    bool WriteU32(uint8_t* target, uint32_t value)
    {
        return target && WriteBytes(target, &value, sizeof(value));
    }

    bool WriteDouble(double* target, double value)
    {
        return target && WriteBytes(target, &value, sizeof(value));
    }

    uint8_t* FindLineGroup(void* collector)
    {
        __try
        {
            auto* c = static_cast<uint8_t*>(collector);
            const uint32_t groups = *reinterpret_cast<uint32_t*>(c + COL_GROUP_COUNT);
            auto* table = *reinterpret_cast<uint8_t**>(c + COL_GROUPS);
            for (uint32_t g = 0; table && g < groups && g < 16; ++g)
            {
                uint8_t* group = table + g * GROUP_STRIDE;
                if (group[0] == LINE_TYPE)
                    return group;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return nullptr;
    }

    bool LineSlotsIdle(uint8_t* group, uint8_t*& slots, uint8_t& count)
    {
        __try
        {
            count = group[1];
            slots = *reinterpret_cast<uint8_t**>(group + GROUP_SLOTS);
            if (!slots || count == 0)
                return false;
            for (uint8_t i = 0; i < count; ++i)
            {
                if (*reinterpret_cast<int*>(slots + i * SLOT_STRIDE + SLOT_STATE) != 0)
                    return false;
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void EnableLongLines(const char* how)
    {
        if (InterlockedExchange(&gResized, 1) != 0)
            return;
        const bool read = WriteU32(gReadSize, LINE_SIZE);
        const bool limit = read && WriteDouble(gLimit, static_cast<double>(LINE_SIZE));
        if (!read || !limit)
        {
            WriteU32(gReadSize, STOCK_LINE_SIZE);
            WriteDouble(gLimit, STOCK_LINE_LIMIT);
            InterlockedExchange(&gResized, 0);
            Log("[SubtitleLines] could not patch the read size / limit - streamed subtitle lines stay at %u bytes.\n",
                STOCK_LINE_SIZE);
            return;
        }
        Log("[SubtitleLines] streamed subtitle lines can now be up to %u bytes (stock %u) - %s.\n", LINE_SIZE,
            STOCK_LINE_SIZE, how);
    }

    bool ResizeExisting(void* collector)
    {
        uint8_t* group = FindLineGroup(collector);
        uint8_t* slots = nullptr;
        uint8_t count = 0;
        if (!group || !LineSlotsIdle(group, slots, count))
        {
            Log("[SubtitleLines] the stream line buffers are busy or missing - left at %u bytes.\n", STOCK_LINE_SIZE);
            return false;
        }

        auto* fresh = static_cast<uint8_t*>(gAlloc(static_cast<size_t>(LINE_SIZE) * count, LINE_TAG));
        if (!fresh)
        {
            Log("[SubtitleLines] no memory for %u-byte stream line buffers - left at %u bytes.\n", LINE_SIZE,
                STOCK_LINE_SIZE);
            return false;
        }

        void* old = nullptr;
        __try
        {
            old = *reinterpret_cast<void**>(slots + SLOT_BUFFER);
            for (uint8_t i = 0; i < count; ++i)
                *reinterpret_cast<uint8_t**>(slots + i * SLOT_STRIDE + SLOT_BUFFER) = fresh + i * LINE_SIZE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            gFree(fresh, LINE_TAG);
            return false;
        }
        if (old)
            gFree(old, LINE_TAG);
        EnableLongLines("buffers replaced after start-up");
        return true;
    }

    void* __fastcall hkCtor(void* collector)
    {
        void* ret = oCtor(collector);
        WriteU32(gAllocSize, STOCK_LINE_SIZE);
        if (FindLineGroup(collector))
        {
            EnableLongLines("buffers made at that size");
            return ret;
        }
        gCreateMemArray(collector, LINE_TYPE, STOCK_LINE_SIZE, LINE_COUNT, LINE_TAG);
        Log("[SubtitleLines] no memory for %u-byte stream line buffers - made the stock %u-byte ones instead.\n",
            LINE_SIZE, STOCK_LINE_SIZE);
        return ret;
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }

    void* CurrentCollector()
    {
        __try
        {
            return gInstance ? *gInstance : nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }
}

bool InstallSubtitleStreamLineLimit(HMODULE hGame)
{
    if (!hGame || !gAddr.SubtitlesBinaryCollector_Constructor || !gAddr.SubtitlesBinaryCollector_CreateMemArray ||
        !gAddr.SubtitlesBinaryCollector_Instance || !gAddr.SubtitlesStreamLineAllocSize ||
        !gAddr.SubtitlesStreamLineReadSize || !gAddr.SubtitlesStreamLineLimit || !gAddr.FoxAllocAnnotated ||
        !gAddr.FoxFreeAnnotated)
    {
        Log("[SubtitleLines] addresses missing for this build - streamed subtitle lines stay at %u bytes.\n",
            STOCK_LINE_SIZE);
        return true;
    }

    void* ctor = Resolve(hGame, gAddr.SubtitlesBinaryCollector_Constructor);
    void* createMemArray = Resolve(hGame, gAddr.SubtitlesBinaryCollector_CreateMemArray);
    void* alloc = Resolve(hGame, gAddr.FoxAllocAnnotated);
    void* freeFn = Resolve(hGame, gAddr.FoxFreeAnnotated);
    gInstance = static_cast<void**>(Resolve(hGame, gAddr.SubtitlesBinaryCollector_Instance));
    gAllocSize = static_cast<uint8_t*>(Resolve(hGame, gAddr.SubtitlesStreamLineAllocSize));
    gReadSize = static_cast<uint8_t*>(Resolve(hGame, gAddr.SubtitlesStreamLineReadSize));
    gLimit = static_cast<double*>(Resolve(hGame, gAddr.SubtitlesStreamLineLimit));

    const uint32_t stockSize = STOCK_LINE_SIZE;
    const double stockLimit = STOCK_LINE_LIMIT;
    if (!CodeMatches(ctor, kCtorPrologue, sizeof(kCtorPrologue)) ||
        !CodeMatches(createMemArray, kCreateMemArrayThunk, sizeof(kCreateMemArrayThunk)) ||
        !CodeMatches(alloc, kAllocPrologue, sizeof(kAllocPrologue)) ||
        !CodeMatches(freeFn, kFreePrologue, sizeof(kFreePrologue)) ||
        !CodeMatches(gAllocSize - sizeof(kAllocOpcode), kAllocOpcode, sizeof(kAllocOpcode)) ||
        !CodeMatches(gReadSize - sizeof(kReadOpcode), kReadOpcode, sizeof(kReadOpcode)) ||
        !CodeMatches(gAllocSize, &stockSize, sizeof(stockSize)) ||
        !CodeMatches(gReadSize, &stockSize, sizeof(stockSize)) || !CodeMatches(gLimit, &stockLimit, sizeof(stockLimit)))
    {
        Log("[SubtitleLines] code is not what this build should have - streamed subtitle lines stay at %u bytes.\n",
            STOCK_LINE_SIZE);
        gInstance = nullptr;
        gAllocSize = gReadSize = nullptr;
        gLimit = nullptr;
        return true;
    }

    gCreateMemArray = reinterpret_cast<CreateMemArray_t>(createMemArray);
    gAlloc = reinterpret_cast<Alloc_t>(alloc);
    gFree = reinterpret_cast<Free_t>(freeFn);

    if (void* collector = CurrentCollector())
    {
        ResizeExisting(collector);
        return true;
    }

    if (!WriteU32(gAllocSize, LINE_SIZE) || MH_CreateHook(ctor, reinterpret_cast<void*>(&hkCtor),
                                                          reinterpret_cast<void**>(&oCtor)) != MH_OK)
    {
        WriteU32(gAllocSize, STOCK_LINE_SIZE);
        Log("[SubtitleLines] hook failed - streamed subtitle lines stay at %u bytes.\n", STOCK_LINE_SIZE);
        return false;
    }
    if (MH_EnableHook(ctor) != MH_OK)
    {
        MH_RemoveHook(ctor);
        WriteU32(gAllocSize, STOCK_LINE_SIZE);
        Log("[SubtitleLines] hook failed - streamed subtitle lines stay at %u bytes.\n", STOCK_LINE_SIZE);
        return false;
    }
    gCtorTarget = ctor;

    if (void* collector = CurrentCollector())
    {
        if (!gResized)
        {
            WriteU32(gAllocSize, STOCK_LINE_SIZE);
            ResizeExisting(collector);
        }
        return true;
    }

    Log("[SubtitleLines] streamed subtitle line buffers will be made %u bytes (stock %u).\n", LINE_SIZE,
        STOCK_LINE_SIZE);
    return true;
}

void RemoveSubtitleStreamLineLimit()
{
    if (gCtorTarget)
    {
        MH_DisableHook(gCtorTarget);
        MH_RemoveHook(gCtorTarget);
        gCtorTarget = nullptr;
    }
    WriteU32(gAllocSize, STOCK_LINE_SIZE);
    WriteU32(gReadSize, STOCK_LINE_SIZE);
    WriteDouble(gLimit, STOCK_LINE_LIMIT);
    InterlockedExchange(&gResized, 0);
}
