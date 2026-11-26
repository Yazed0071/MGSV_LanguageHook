#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

bool FoxAssetExists(uint64_t code);

namespace
{
    using SetGradeMark_t = uint64_t(__fastcall*)(void* self, void* node, uint64_t grade, uint64_t style, uint64_t alternate);
    using GetUix_t = void*(__cdecl*)();
    using SetTexture_t = uint64_t(__fastcall*)(void* uix, void* node, uint64_t texture, uint64_t parameter);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t NODE_PARENT = 0x10;
    constexpr size_t NODE_NAME = 0x6C;
    constexpr size_t VT_SET_TEXTURE = 0x518;
    constexpr int MAX_PARENT_DEPTH = 16;
    constexpr uint32_t GRADE_MARK_ROOT = 0x2D742FA2;
    constexpr uint64_t BASE_TEXTURE = 0xCAFB3BBF9889ull;
    constexpr uint64_t TAG_RTL = 0x1568FFDC95CB6BA9ull;
    constexpr uint64_t TAG_2_RTL = 0x156857838D18B4CFull;
    constexpr uint8_t LAST_FIRST_ATLAS_GRADE = 11;
    constexpr uint8_t LAST_GRADE = 15;

    const uint8_t kPrologue[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89,
        0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x0F, 0xB6, 0xD9,
    };

    SetGradeMark_t oSetGradeMark = nullptr;
    GetUix_t gGetUix = nullptr;
    void* gTarget = nullptr;
    std::atomic<bool> gLoggedApplied{ false };
    std::atomic<bool> gLoggedMissing{ false };

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

    bool IsRightToLeftSafe()
    {
        __try
        {
            return RL_IsRightToLeft();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    uint32_t RootName(const uint8_t* node)
    {
        __try
        {
            const uint8_t* walk = node;
            for (int depth = 0; depth < MAX_PARENT_DEPTH; ++depth)
            {
                const uint8_t* up = *reinterpret_cast<const uint8_t* const*>(walk + NODE_PARENT);
                if (!up)
                    break;
                walk = up;
            }
            return *reinterpret_cast<const uint32_t*>(walk + NODE_NAME);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    bool SetTexture(void* node, uint64_t texture)
    {
        __try
        {
            void* uix = gGetUix ? gGetUix() : nullptr;
            if (!uix)
                return false;
            const auto setTexture = *reinterpret_cast<SetTexture_t*>(*reinterpret_cast<uint8_t**>(uix) + VT_SET_TEXTURE);
            setTexture(uix, node, texture, BASE_TEXTURE);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    uint64_t __fastcall hkSetGradeMark(void* self, void* node, uint64_t grade, uint64_t style, uint64_t alternate)
    {
        const uint64_t result = oSetGradeMark(self, node, grade, style, alternate);
        const uint8_t value = static_cast<uint8_t>(grade);
        if (!node || value < 1 || value > LAST_GRADE || !IsRightToLeftSafe())
            return result;
        if (RootName(static_cast<const uint8_t*>(node)) != GRADE_MARK_ROOT)
            return result;
        const uint64_t texture = value <= LAST_FIRST_ATLAS_GRADE ? TAG_RTL : TAG_2_RTL;
        if (!FoxAssetExists(texture))
        {
            if (!gLoggedMissing.exchange(true))
                Log("[GradeMark] right-to-left tag texture 0x%llX not found - the stock tag is kept.\n",
                    static_cast<unsigned long long>(texture));
            return result;
        }
        if (SetTexture(node, texture) && !gLoggedApplied.exchange(true))
            Log("[GradeMark] grade tags point right in right-to-left lists (grade %u).\n", static_cast<unsigned>(value));
        return result;
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallGradeMarkRtlHook(HMODULE hGame)
{
    if (!hGame || !gAddr.GradeMark_SetGrade || !gAddr.GetUixUtilityToFeedQuarkEnvironment)
    {
        Log("[GradeMark] address missing - grade tags keep the stock direction.\n");
        return true;
    }
    gGetUix = reinterpret_cast<GetUix_t>(Resolve(hGame, gAddr.GetUixUtilityToFeedQuarkEnvironment));
    void* target = Resolve(hGame, gAddr.GradeMark_SetGrade);
    if (!CodeMatches(target, kPrologue, sizeof(kPrologue)))
    {
        Log("[GradeMark] prologue mismatch at %p - grade tags keep the stock direction.\n", target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkSetGradeMark), reinterpret_cast<void**>(&oSetGradeMark)) != MH_OK)
    {
        Log("[GradeMark] MH_CreateHook failed.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[GradeMark] MH_EnableHook failed.\n");
        return true;
    }
    gTarget = target;
    Log("[GradeMark] grade tag setter hooked at %p.\n", target);
    return true;
}

void RemoveGradeMarkRtlHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oSetGradeMark = nullptr;
    gGetUix = nullptr;
    gLoggedApplied = false;
    gLoggedMissing = false;
}
