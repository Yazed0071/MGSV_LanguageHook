#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <mutex>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

void ArabicScrollStampRtlNode(void* node);
void ArabicScrollReleaseFittingNode(void* node);

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using GetDisplayWidth_t = float(__fastcall*)(void* node);

    using SetCircleCursorFromSrickDir_t =
        void(__fastcall*)(void* thisPtr, uint32_t param2, uint32_t param3, uint8_t param4);

    using EquipCrossUpdate_t = void(__fastcall*)(void* thisPtr);
    using NodeCall_t = void(__fastcall*)(void* node);

    static NodeCall_t gStopTextScroll = nullptr;
    static NodeCall_t gDisableStencilArea = nullptr;

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static GetDisplayWidth_t gGetDisplayWidth = nullptr;
    static SetCircleCursorFromSrickDir_t gOrigSetCircleCursor = nullptr;
    static EquipCrossUpdate_t gOrigUpdate = nullptr;

    static void* gTarget = nullptr;
    static void* gUpdateTarget = nullptr;

    static constexpr uintptr_t kImageBase = 0x140000000ull;

    static constexpr uint8_t ALIGN_LEFT = 0;
    static constexpr uint8_t ALIGN_RIGHT = 2;
    static constexpr uint8_t ALIGN_DEFER = 3;

    static constexpr size_t OFF_ALIGN = 0xD8;
    static constexpr size_t OFF_ALIGN_DRIVER = 0xDA;
    static constexpr size_t OFF_TEXT_WIDTH = 0x17C;
    static constexpr size_t OFF_FLAGS = 0x90;
    static constexpr uint16_t FLAG_REBUILD = 0x10;

    static constexpr size_t kDescriptionNameNode = 0x218;
    static constexpr size_t kDescriptionBodyNode = 0x220;


    struct OriginalAlign
    {
        uint8_t align;
        uint8_t driver;
    };

    static std::unordered_map<void*, OriginalAlign> gOriginalAlign;
    static std::mutex gAlignMutex;
}

static uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - kImageBase);
}

static bool IsArabicSafe()
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

static bool SafeReadPtr(const void* addr, void*& out)
{
    __try
    {
        out = *reinterpret_cast<void* const*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = nullptr;
        return false;
    }
}

static bool SafeReadU8(const void* addr, uint8_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint8_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

static bool SafeReadU32(const void* addr, uint32_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint32_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

static bool SafeReadF(const void* addr, float& out)
{
    __try
    {
        out = *reinterpret_cast<const float*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0.0f;
        return false;
    }
}

static bool SafeWriteU8(void* addr, uint8_t value)
{
    __try
    {
        *reinterpret_cast<uint8_t*>(addr) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static float SafeDisplayWidth(void* node)
{
    if (!gGetDisplayWidth)
        return 0.0f;

    __try
    {
        return gGetDisplayWidth(node);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0.0f;
    }
}

static bool CacheOriginalAlign(void* node, OriginalAlign& out)
{
    uint8_t align = 0;
    uint8_t driver = 0;

    if (!SafeReadU8(reinterpret_cast<uint8_t*>(node) + OFF_ALIGN, align))
        return false;
    if (!SafeReadU8(reinterpret_cast<uint8_t*>(node) + OFF_ALIGN_DRIVER, driver))
        return false;

    std::lock_guard<std::mutex> lock(gAlignMutex);

    const auto it = gOriginalAlign.find(node);
    if (it == gOriginalAlign.end())
    {
        const OriginalAlign fresh{ align, driver };
        gOriginalAlign.emplace(node, fresh);
        out = fresh;
        return true;
    }

    out = it->second;
    return true;
}

static void WriteAlign(void* node, uint8_t align, uint8_t driver)
{
    SafeWriteU8(reinterpret_cast<uint8_t*>(node) + OFF_ALIGN, align);
    SafeWriteU8(reinterpret_cast<uint8_t*>(node) + OFF_ALIGN_DRIVER, driver);
}

static void MarkRebuild(void* node)
{
    __try
    {
        *reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(node) + OFF_FLAGS) |= FLAG_REBUILD;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static void StopLeftoverScroll(void* node)
{
    if (!gStopTextScroll || !gDisableStencilArea)
        return;
    uint8_t state = 0;
    if (!SafeReadU8(reinterpret_cast<uint8_t*>(node) + 0x92, state) || state == 0)
        return;
    __try
    {
        gStopTextScroll(node);
        gDisableStencilArea(node);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static void ApplyRightAlignIfFits(void* node, bool reverseMarquee, bool requireAuthoredLeft)
{
    OriginalAlign original{};
    if (!CacheOriginalAlign(node, original))
        return;

    if (requireAuthoredLeft && original.align != ALIGN_LEFT)
        return;

    float textWidth = 0.0f;
    SafeReadF(reinterpret_cast<uint8_t*>(node) + OFF_TEXT_WIDTH, textWidth);

    const float displayWidth = SafeDisplayWidth(node);

    if (displayWidth > 0.0f && textWidth > displayWidth)
    {
        WriteAlign(node, ALIGN_LEFT, ALIGN_DEFER);

        if (reverseMarquee)
            ArabicScrollStampRtlNode(node);

        return;
    }

    if (reverseMarquee && textWidth > 0.0f)
    {
        ArabicScrollReleaseFittingNode(node);
        StopLeftoverScroll(node);
    }
    WriteAlign(node, ALIGN_RIGHT, ALIGN_RIGHT);
}

static void ApplyDescriptionNode(void* node)
{
    if (!node)
        return;

    ApplyRightAlignIfFits(node, true, false);
}

static void RestoreNode(void* node)
{
    if (!node)
        return;

    OriginalAlign original{};
    {
        std::lock_guard<std::mutex> lock(gAlignMutex);
        const auto it = gOriginalAlign.find(node);
        if (it == gOriginalAlign.end())
            return;
        original = it->second;
        gOriginalAlign.erase(it);
    }

    WriteAlign(node, original.align, original.driver);
    MarkRebuild(node);
    ArabicScrollReleaseFittingNode(node);

    float textWidth = 0.0f;
    SafeReadF(reinterpret_cast<uint8_t*>(node) + OFF_TEXT_WIDTH, textWidth);
    const float displayWidth = SafeDisplayWidth(node);
    if (displayWidth > 0.0f && textWidth > 0.0f && textWidth <= displayWidth)
        StopLeftoverScroll(node);
}

static void ForEachDescriptionNode(void* thisPtr, void (*fn)(void*))
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    static const size_t kOffsets[] = { kDescriptionBodyNode, kDescriptionNameNode };

    for (size_t i = 0; i < _countof(kOffsets); ++i)
    {
        void* node = nullptr;
        if (SafeReadPtr(base + kOffsets[i], node) && node)
            fn(node);
    }
}

static void __fastcall hkSetCircleCursorFromSrickDir(
    void* thisPtr,
    uint32_t param2,
    uint32_t param3,
    uint8_t param4)
{
    if (gOrigSetCircleCursor)
        gOrigSetCircleCursor(thisPtr, param2, param3, param4);

    if (!thisPtr)
        return;

    if (IsArabicSafe())
        ForEachDescriptionNode(thisPtr, &ApplyDescriptionNode);
    else
        ForEachDescriptionNode(thisPtr, &RestoreNode);
}

static void __fastcall hkEquipCrossUpdate(void* thisPtr)
{
    if (gOrigUpdate)
        gOrigUpdate(thisPtr);

    if (!thisPtr)
        return;

    if (IsArabicSafe())
        ForEachDescriptionNode(thisPtr, &ApplyDescriptionNode);
    else
        ForEachDescriptionNode(thisPtr, &RestoreNode);
}

bool InstallEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.IsArabLanguage || !gAddr.EquipCrossEvCall_SetCircleCursorFromSrickDir)
    {
        Log("[EquipCrossEvCall::SetCircleCursorFromSrickDir] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;

    static const uint8_t kStopTextScroll[] = { 0x33, 0xC0, 0x48, 0x89, 0x81, 0xB4, 0x01, 0x00, 0x00, 0x88, 0x81, 0x92 };
    static const uint8_t kDisableStencil[] = { 0xB8, 0xFD, 0xFF, 0x00, 0x00, 0x66, 0x21, 0x81, 0x90, 0x00, 0x00, 0x00 };
    if (gAddr.ModelNodeText_StopTextScroll && gAddr.ModelNodeText_DisableStencilArea)
    {
        void* stop = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.ModelNodeText_StopTextScroll));
        void* stencil = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.ModelNodeText_DisableStencilArea));
        if (std::memcmp(stop, kStopTextScroll, sizeof(kStopTextScroll)) == 0 &&
            std::memcmp(stencil, kDisableStencil, sizeof(kDisableStencil)) == 0)
        {
            gStopTextScroll = reinterpret_cast<NodeCall_t>(stop);
            gDisableStencilArea = reinterpret_cast<NodeCall_t>(stencil);
        }
    }

    if (gAddr.ModelNodeText_GetDisplayWidth)
    {
        gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(
            ToRuntimeVA(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    }
    else
    {
        Log("[EquipCrossEvCall::SetCircleCursorFromSrickDir] No GetDisplayWidth; "
            "overflowing slot labels will stay left-aligned.\n");
    }

    gTarget = reinterpret_cast<void*>(
        ToRuntimeVA(hGame, gAddr.EquipCrossEvCall_SetCircleCursorFromSrickDir));

    if (MH_CreateHook(gTarget, &hkSetCircleCursorFromSrickDir,
        reinterpret_cast<LPVOID*>(&gOrigSetCircleCursor)) != MH_OK)
    {
        Log("[EquipCrossEvCall::SetCircleCursorFromSrickDir] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[EquipCrossEvCall::SetCircleCursorFromSrickDir] MH_EnableHook failed.\n");
        return false;
    }

    Log("[EquipCrossEvCall::SetCircleCursorFromSrickDir] Arabic align hook enabled.\n");

    if (gAddr.EquipCrossEvCall_Update)
    {
        gUpdateTarget = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.EquipCrossEvCall_Update));

        if (MH_CreateHook(gUpdateTarget, &hkEquipCrossUpdate,
            reinterpret_cast<LPVOID*>(&gOrigUpdate)) == MH_OK &&
            MH_EnableHook(gUpdateTarget) == MH_OK)
        {
            Log("[EquipCrossEvCall::Update] Per-frame description align hook enabled.\n");
        }
        else
        {
            Log("[EquipCrossEvCall::Update] Hook failed.\n");
            gUpdateTarget = nullptr;
        }
    }
    else
    {
        Log("[EquipCrossEvCall::Update] No address for this build.\n");
    }

    return true;
}

void RemoveEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    if (gUpdateTarget)
    {
        MH_DisableHook(gUpdateTarget);
        MH_RemoveHook(gUpdateTarget);
        gUpdateTarget = nullptr;
    }

    gOrigSetCircleCursor = nullptr;
    gOrigUpdate = nullptr;
    gIsArabLanguage = nullptr;
    gGetDisplayWidth = nullptr;
    gStopTextScroll = nullptr;
    gDisableStencilArea = nullptr;

    std::lock_guard<std::mutex> lock(gAlignMutex);
    gOriginalAlign.clear();

    Log("[EquipCrossEvCall::SetCircleCursorFromSrickDir] Arabic align hook removed.\n");
}
