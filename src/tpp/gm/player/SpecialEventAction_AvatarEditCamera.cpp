#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "log.h"
#include "AddressSet.h"

namespace
{
    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFFSET_SIZE = 16;
    constexpr size_t SIDE_BYTE = 3;
    constexpr uint8_t SIDE_HEAD_RIGHT = 0xBE;
    constexpr uint8_t SIDE_HEAD_LEFT = 0x3E;

    const uint8_t kOffset[OFFSET_SIZE] = { 0xB8, 0x1E, 0x05, 0xBE, 0x8F, 0xC2, 0xF5, 0x3C,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    std::atomic<uint8_t*> gOffset{ nullptr };
    std::atomic<int> gLogBudget{ 8 };

    bool ReadBytes(const uint8_t* source, uint8_t* out, size_t size)
    {
        __try
        {
            std::memcpy(out, source, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool WriteByte(uint8_t* target, uint8_t value)
    {
        __try
        {
            *target = value;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool IsKnownOffset(const uint8_t* bytes)
    {
        for (size_t i = 0; i < OFFSET_SIZE; ++i)
        {
            if (i == SIDE_BYTE)
            {
                if (bytes[i] != SIDE_HEAD_RIGHT && bytes[i] != SIDE_HEAD_LEFT)
                    return false;
            }
            else if (bytes[i] != kOffset[i])
            {
                return false;
            }
        }
        return true;
    }

    bool WriteSide(uint8_t* offset, uint8_t side)
    {
        uint8_t* target = offset + SIDE_BYTE;
        MEMORY_BASIC_INFORMATION info = {};
        if (VirtualQuery(target, &info, sizeof(info)) != sizeof(info) || info.State != MEM_COMMIT)
            return false;
        const DWORD executable = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        const DWORD writable = (info.Protect & executable) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        DWORD previous = 0;
        if (!VirtualProtect(target, 1, writable, &previous))
            return false;
        const bool written = WriteByte(target, side);
        DWORD ignored = 0;
        VirtualProtect(target, 1, previous, &ignored);
        return written;
    }
}

bool InitAvatarEditCameraMirror(HMODULE hGame)
{
    if (!hGame || !gAddr.AvatarEdit_CameraOffset)
    {
        Log("[AvatarEditCamera] address missing - the avatar editor keeps its original layout.\n");
        return false;
    }
    uint8_t* offset = reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(hGame) +
                                                 (gAddr.AvatarEdit_CameraOffset - IDA_IMAGE_BASE));
    uint8_t now[OFFSET_SIZE] = {};
    if (!ReadBytes(offset, now, sizeof(now)) || !IsKnownOffset(now))
    {
        Log("[AvatarEditCamera] camera offset at %p is not the expected value - the avatar editor keeps its original "
            "layout.\n",
            offset);
        return false;
    }
    gOffset.store(offset, std::memory_order_release);
    Log("[AvatarEditCamera] camera offset found at %p (head on the %s).\n", offset,
        now[SIDE_BYTE] == SIDE_HEAD_LEFT ? "left" : "right");
    return true;
}

bool AvatarEditCameraMirrorReady()
{
    return gOffset.load(std::memory_order_acquire) != nullptr;
}

void SetAvatarEditCameraMirror(bool headLeft)
{
    uint8_t* offset = gOffset.load(std::memory_order_acquire);
    if (!offset)
        return;
    const uint8_t wanted = headLeft ? SIDE_HEAD_LEFT : SIDE_HEAD_RIGHT;
    uint8_t now[OFFSET_SIZE] = {};
    if (!ReadBytes(offset, now, sizeof(now)) || !IsKnownOffset(now) || now[SIDE_BYTE] == wanted)
        return;
    const bool written = WriteSide(offset, wanted);
    if (gLogBudget.load() > 0 && gLogBudget.fetch_sub(1) > 0)
        Log("[AvatarEditCamera] head moved to the %s side of the screen%s.\n", headLeft ? "left" : "right",
            written ? "" : " - FAILED, the write was refused");
}

void ShutdownAvatarEditCameraMirror()
{
    SetAvatarEditCameraMirror(false);
    gOffset.store(nullptr, std::memory_order_release);
}
