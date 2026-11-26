#include <windows.h>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

using IsArabLanguage_t = bool(__cdecl*)();
using SetMissionInfoTexts_t = void(__fastcall*)(void* thisPtr);
using GetUix_t = void*(__cdecl*)();
using SetTranslate_t = uint64_t(__fastcall*)(void* uix, void* node, const float* translate);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static SetMissionInfoTexts_t oSetMissionInfoTexts = nullptr;
static void* gTargetSetMissionInfoTexts = nullptr;
static GetUix_t gGetUix = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

static constexpr size_t kTitleBufferOffset = 0x250;
static constexpr size_t kTitleBufferSize = 0xFF;

static constexpr size_t kMissionInfoModelOffset = 0x568;
static constexpr size_t kMissionCategoryNodeOffset = 0x570;
static constexpr size_t kMissionTitleNodeOffset = 0x578;
static constexpr size_t kMissionSubgoalNodeOffset = 0x580;
static constexpr size_t kMissionInfoNodeOffset = 0x588;
static constexpr size_t kHardModeNodeOffset = 0x590;
static constexpr size_t kElapsedTimeValueNodeOffset = 0x598;
static constexpr size_t kSkillTitleNodeOffset = 0xA28;

static constexpr size_t MODEL_ROOT = 0x80;
static constexpr size_t MODEL_NODE_COUNT = 0x90;
static constexpr size_t MODEL_NODES = 0x98;
static constexpr size_t NODE_PARENT = 0x10;
static constexpr size_t NODE_TRANSLATION = 0x20;
static constexpr size_t NODE_NAME = 0x6C;
static constexpr size_t TEXT_UNITS = 0x138;
static constexpr size_t TEXT_UNIT_COUNT = 0x140;
static constexpr size_t UNIT_STRIDE = 0x20;
static constexpr size_t UNIT_LINE = 0x12;
static constexpr size_t VT_SET_TRANSLATE = 0x340;
static constexpr uint32_t kMissionInfoRootName = 0x5FC4096B;
static constexpr uint32_t kElapsedTimeBackgroundName = 0x66349C2C;
static constexpr uint32_t kSkillBlockRootName = 0x6274CF8D;
static constexpr uint32_t kMaxModelNodes = 400;
static constexpr uint32_t kMaxTextUnits = 64;
static constexpr uint32_t kDescriptionLinesReachingTimeRow = 4;
static constexpr float kDescriptionLinePitch = 2.1f;
static constexpr float kElapsedTimeRowGap = 0.3f;
static constexpr float kPositionEpsilon = 0.01f;

struct ElapsedTimeRowNode
{
    uint8_t* node;
    float authored;
    float applied;
};

static ElapsedTimeRowNode gElapsedTimeRow[4] = {};
static std::atomic<int> gElapsedTimeRowLogged{ -1 };

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

static void ForceRightAlignNode(void* node)
{
    if (!node)
        return;

    SafeWriteU8(reinterpret_cast<uint8_t*>(node) + 0xD8, TEXT_ALIGN_RIGHT);
}

static void ApplyArabicAlignment(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* node = nullptr;

    if (SafeReadPtr(base + kMissionCategoryNodeOffset, node))
        ForceRightAlignNode(node);

    if (SafeReadPtr(base + kMissionTitleNodeOffset, node))
        ForceRightAlignNode(node);

    if (SafeReadPtr(base + kMissionSubgoalNodeOffset, node))
        ForceRightAlignNode(node);

    if (SafeReadPtr(base + kMissionInfoNodeOffset, node))
        ForceRightAlignNode(node);

    if (SafeReadPtr(base + kHardModeNodeOffset, node))
        ForceRightAlignNode(node);
}

static uint32_t DescriptionLineCount(const uint8_t* base)
{
    __try
    {
        const uint8_t* node = *reinterpret_cast<const uint8_t* const*>(base + kMissionInfoNodeOffset);
        if (!node)
            return 0;
        const uint8_t* units = *reinterpret_cast<const uint8_t* const*>(node + TEXT_UNITS);
        const uint32_t count = *reinterpret_cast<const uint32_t*>(node + TEXT_UNIT_COUNT);
        if (!units || count == 0 || count > kMaxTextUnits)
            return 0;
        uint32_t lines = 0;
        for (uint32_t i = 0; i < count; ++i)
        {
            const uint32_t line = *reinterpret_cast<const uint16_t*>(units + i * UNIT_STRIDE + UNIT_LINE);
            if (line + 1 > lines)
                lines = line + 1;
        }
        return lines;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

static uint8_t* FindMissionInfoNode(const uint8_t* model, uint32_t name)
{
    if (!model)
        return nullptr;
    __try
    {
        const uint8_t* root = *reinterpret_cast<const uint8_t* const*>(model + MODEL_ROOT);
        if (!root || *reinterpret_cast<const uint32_t*>(root + NODE_NAME) != kMissionInfoRootName)
            return nullptr;
        const uint32_t count = *reinterpret_cast<const uint32_t*>(model + MODEL_NODE_COUNT);
        uint8_t* const* nodes = *reinterpret_cast<uint8_t* const* const*>(model + MODEL_NODES);
        if (!nodes || count == 0 || count > kMaxModelNodes)
            return nullptr;
        for (uint32_t i = 0; i < count; ++i)
        {
            uint8_t* node = nodes[i];
            if (node && *reinterpret_cast<const uint32_t*>(node + NODE_NAME) == name)
                return node;
        }
        return nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
}

static bool ReadNodeTranslation(const uint8_t* node, float* out)
{
    __try
    {
        std::memcpy(out, node + NODE_TRANSLATION, 4 * sizeof(float));
        return std::isfinite(out[1]);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static uint8_t* SkillBlockRoot(void* title)
{
    void* parent = nullptr;
    if (!title || !SafeReadPtr(reinterpret_cast<uint8_t*>(title) + NODE_PARENT, parent) || !parent)
        return nullptr;
    __try
    {
        if (*reinterpret_cast<const uint32_t*>(reinterpret_cast<uint8_t*>(parent) + NODE_NAME) != kSkillBlockRootName)
            return nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
    return reinterpret_cast<uint8_t*>(parent);
}

static bool SetNodeY(uint8_t* node, float y)
{
    if (!gGetUix || !node)
        return false;
    alignas(16) float translate[4] = {};
    if (!ReadNodeTranslation(node, translate))
        return false;
    translate[1] = y;
    __try
    {
        void* uix = gGetUix();
        if (!uix)
            return false;
        void** vt = *reinterpret_cast<void***>(uix);
        reinterpret_cast<SetTranslate_t>(vt[VT_SET_TRANSLATE / sizeof(void*)])(uix, node, translate);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void PlaceElapsedTimeRow(void* thisPtr, bool arabic)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    void* label = nullptr;
    void* value = nullptr;
    void* model = nullptr;
    void* skillTitle = nullptr;
    SafeReadPtr(base + kHardModeNodeOffset, label);
    SafeReadPtr(base + kElapsedTimeValueNodeOffset, value);
    SafeReadPtr(base + kMissionInfoModelOffset, model);
    SafeReadPtr(base + kSkillTitleNodeOffset, skillTitle);
    uint8_t* background = FindMissionInfoNode(reinterpret_cast<uint8_t*>(model), kElapsedTimeBackgroundName);
    uint8_t* nodes[4] = { reinterpret_cast<uint8_t*>(label), reinterpret_cast<uint8_t*>(value), background,
                          SkillBlockRoot(skillTitle) };

    const uint32_t lines = arabic ? DescriptionLineCount(base) : 0;
    const bool complete = label && value && background && gGetUix;
    const bool lower = arabic && complete && lines >= kDescriptionLinesReachingTimeRow;
    const float shift = lower ? -(static_cast<float>(lines - kDescriptionLinesReachingTimeRow + 1) * kDescriptionLinePitch -
                                  kElapsedTimeRowGap)
                              : 0.0f;

    for (size_t i = 0; i < 4; ++i)
    {
        uint8_t* node = nodes[i];
        if (!node)
            continue;
        ElapsedTimeRowNode& entry = gElapsedTimeRow[i];
        alignas(16) float translate[4] = {};
        if (!ReadNodeTranslation(node, translate))
            continue;
        if (entry.node != node || std::fabs(translate[1] - (entry.authored + entry.applied)) > kPositionEpsilon)
            entry = { node, translate[1], 0.0f };
        if (std::fabs(entry.applied - shift) > kPositionEpsilon && SetNodeY(node, entry.authored + shift))
            entry.applied = shift;
    }

    if (!arabic)
        return;
    const int state = lower ? static_cast<int>(lines) : 0;
    if (gElapsedTimeRowLogged.exchange(state) != state)
        Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] description has %u lines -> elapsed-time row and skills "
            "%s %.2f (label %p, time %p, background %p, skills %p)\n",
            lines, lower ? "lowered by" : "kept, shift", -shift, label, value, background, nodes[3]);
}

static void TrimAsciiSpaces(char* s)
{
    if (!s)
        return;

    size_t len = std::strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'))
    {
        s[len - 1] = '\0';
        --len;
    }
}

static void RewriteMissionTitleBufferArabic(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* outBuf = reinterpret_cast<char*>(reinterpret_cast<uint8_t*>(thisPtr) + kTitleBufferOffset);
    if (!outBuf || !outBuf[0])
        return;

    char original[kTitleBufferSize + 1]{};
    strncpy_s(original, outBuf, _TRUNCATE);

    char* firstSpace = std::strchr(original, ' ');
    if (!firstSpace)
        return;

    *firstSpace = '\0';
    char* partA = original;
    char* partB = firstSpace + 1;

    while (*partB == ' ' || *partB == '\t')
        ++partB;

    if (!partA[0] || !partB[0])
        return;

    TrimAsciiSpaces(partA);
    TrimAsciiSpaces(partB);

    if (!partA[0] || !partB[0])
        return;

    char rebuilt[kTitleBufferSize + 1]{};
    _snprintf_s(rebuilt, sizeof(rebuilt), _TRUNCATE, "%s %s", partB, partA);
    strncpy_s(outBuf, kTitleBufferSize + 1, rebuilt, _TRUNCATE);
}

static void __fastcall hkSetMissionInfoTexts(void* thisPtr)
{
    if (!thisPtr || !oSetMissionInfoTexts)
        return;

    oSetMissionInfoTexts(thisPtr);

    if (!IsArabicSafe())
    {
        PlaceElapsedTimeRow(thisPtr, false);
        return;
    }

    ApplyArabicAlignment(thisPtr);
    PlaceElapsedTimeRow(thisPtr, true);
}

bool InstallMbDvcMissionInfoSetMissionInfoTextsArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage = &RL_IsRightToLeft;
    if (gAddr.GetUixUtilityToFeedQuarkEnvironment)
        gGetUix = reinterpret_cast<GetUix_t>(ToRuntimeVA(hGame, gAddr.GetUixUtilityToFeedQuarkEnvironment));

    gTargetSetMissionInfoTexts =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetMissionInfoTexts));

    if (!gTargetSetMissionInfoTexts)
    {
        Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetSetMissionInfoTexts,
            reinterpret_cast<void*>(&hkSetMissionInfoTexts),
            reinterpret_cast<void**>(&oSetMissionInfoTexts));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetSetMissionInfoTexts);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] Hook enabled.\n");
    return true;
}

void RemoveMbDvcMissionInfoSetMissionInfoTextsArabicHook()
{
    if (gTargetSetMissionInfoTexts)
    {
        MH_DisableHook(gTargetSetMissionInfoTexts);
        MH_RemoveHook(gTargetSetMissionInfoTexts);
        gTargetSetMissionInfoTexts = nullptr;
    }

    oSetMissionInfoTexts = nullptr;
    gIsArabLanguage = nullptr;
    gGetUix = nullptr;
    for (ElapsedTimeRowNode& entry : gElapsedTimeRow)
        entry = {};
    gElapsedTimeRowLogged = -1;
}