#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

using IsArabLanguage_t = bool(__cdecl*)();
using SetMainText_t = uint64_t(__fastcall*)(void* thisPtr, void* textUnit, unsigned int maxUnits, const char* text);
using GetDisplayWidth_t = float(__fastcall*)(void* node);
using GetUix_t = void*(__cdecl*)();
using SetTranslateX_t = void(__fastcall*)(void* uix, void* node, float x);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static SetMainText_t oSetMainText = nullptr;
static void* gTargetSetMainText = nullptr;
static GetDisplayWidth_t gGetDisplayWidth = nullptr;
static GetUix_t gGetUix = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;
static constexpr size_t LAYOUT_TITLE = 0x10;
static constexpr size_t LAYOUT_BODY = 0x18;
static constexpr size_t LAYOUT_ICON = 0x20;
static constexpr size_t NODE_TRANSLATION = 0x20;
static constexpr size_t NODE_SIZE = 0x40;
static constexpr size_t NODE_FLAGS = 0x90;
static constexpr size_t NODE_LINE_ALIGN = 0xD8;
static constexpr uint16_t FLAG_REBUILD = 0x10;
static constexpr size_t VT_SET_TRANSLATE_X = 0x350;
static constexpr float PIXEL_TO_TRANSLATE = 0.1f;
static constexpr size_t MAX_AUTHORED = 32;

struct AuthoredNode
{
    void* node;
    float x;
    uint8_t line;
    bool moved;
};

static AuthoredNode gAuthored[MAX_AUTHORED] = {};
static size_t gAuthoredNext = 0;
static bool gHeaderLogged = false;

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

static void ForceNodeAlign(void* modelNodeText, uint8_t align)
{
    if (!modelNodeText)
        return;

    SafeWriteU8(reinterpret_cast<uint8_t*>(modelNodeText) + 0xD8, align);
}

static void* GetBodyTextNode(void* thisPtr)
{
    if (!thisPtr)
        return nullptr;

    void* node = nullptr;
    SafeReadPtr(reinterpret_cast<uint8_t*>(thisPtr) + 0x18, node);
    return node;
}

static bool ReadNodeX(const void* node, float& x, uint8_t& line)
{
    __try
    {
        x = *reinterpret_cast<const float*>(static_cast<const uint8_t*>(node) + NODE_TRANSLATION);
        line = static_cast<const uint8_t*>(node)[NODE_LINE_ALIGN];
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static float ReadHalfSize(const void* node)
{
    __try
    {
        const float size = *reinterpret_cast<const float*>(static_cast<const uint8_t*>(node) + NODE_SIZE);
        if (size > 0.0f && size < 200.0f)
            return size * PIXEL_TO_TRANSLATE * 0.5f;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return 0.0f;
}

static AuthoredNode* AuthoredFor(void* node)
{
    if (!node)
        return nullptr;
    for (AuthoredNode& entry : gAuthored)
    {
        if (entry.node == node)
            return &entry;
    }
    float x = 0.0f;
    uint8_t line = 0;
    if (!ReadNodeX(node, x, line))
        return nullptr;
    AuthoredNode& slot = gAuthored[gAuthoredNext++ % MAX_AUTHORED];
    slot = { node, x, line, false };
    return &slot;
}

static float DisplayWidth(void* node)
{
    if (!gGetDisplayWidth || !node)
        return -1.0f;
    __try
    {
        return gGetDisplayWidth(node);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return -1.0f;
    }
}

static void SetNodeX(void* node, float x)
{
    if (!gGetUix || !node)
        return;
    __try
    {
        void* uix = gGetUix();
        if (!uix)
            return;
        void** vt = *reinterpret_cast<void***>(uix);
        reinterpret_cast<SetTranslateX_t>(vt[VT_SET_TRANSLATE_X / sizeof(void*)])(uix, node, x);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static void SetLineAlign(void* node, uint8_t align)
{
    __try
    {
        uint8_t* bytes = static_cast<uint8_t*>(node);
        if (bytes[NODE_LINE_ALIGN] == align)
            return;
        bytes[NODE_LINE_ALIGN] = align;
        *reinterpret_cast<uint16_t*>(bytes + NODE_FLAGS) |= FLAG_REBUILD;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static void MirrorHeader(void* layout, bool arabic)
{
    if (!layout)
        return;
    void* title = nullptr;
    void* body = nullptr;
    void* icon = nullptr;
    SafeReadPtr(static_cast<uint8_t*>(layout) + LAYOUT_TITLE, title);
    SafeReadPtr(static_cast<uint8_t*>(layout) + LAYOUT_BODY, body);
    SafeReadPtr(static_cast<uint8_t*>(layout) + LAYOUT_ICON, icon);
    if (!title || !body || !icon)
        return;
    AuthoredNode* titleAuthored = AuthoredFor(title);
    AuthoredNode* iconAuthored = AuthoredFor(icon);
    if (!titleAuthored || !iconAuthored)
        return;

    if (!arabic)
    {
        if (titleAuthored->moved)
        {
            SetNodeX(title, titleAuthored->x);
            SetLineAlign(title, titleAuthored->line);
            titleAuthored->moved = false;
        }
        if (iconAuthored->moved)
        {
            SetNodeX(icon, iconAuthored->x);
            iconAuthored->moved = false;
        }
        return;
    }

    float bodyX = 0.0f;
    uint8_t bodyLine = 0;
    const float bodyWidth = DisplayWidth(body);
    const float titleWidth = DisplayWidth(title);
    if (!ReadNodeX(body, bodyX, bodyLine) || !(bodyWidth > 0.0f) || !(titleWidth > 0.0f))
        return;

    const float bodyRight = bodyX + bodyWidth * PIXEL_TO_TRANSLATE;
    const float mirror = bodyX + bodyRight;
    float iconX = mirror - iconAuthored->x;
    float titleX = mirror - titleAuthored->x - titleWidth * PIXEL_TO_TRANSLATE;
    const float overhang = iconX + ReadHalfSize(icon) - bodyRight;
    if (overhang > 0.0f)
    {
        iconX -= overhang;
        titleX -= overhang;
    }
    SetNodeX(icon, iconX);
    SetNodeX(title, titleX);
    SetLineAlign(title, TEXT_ALIGN_RIGHT);
    titleAuthored->moved = true;
    iconAuthored->moved = true;

    if (!gHeaderLogged)
    {
        gHeaderLogged = true;
        Log("[MbLogViewerEv::BodyLayout] Arabic speaker header mirrored across the body box (x %.2f, width %.1f): "
            "icon %.2f -> %.2f, name %.2f -> %.2f (box %.1f), name right-aligned\n",
            bodyX, bodyWidth, iconAuthored->x, iconX, titleAuthored->x, titleX, titleWidth);
    }
}

static uint64_t __fastcall hkSetMainText(void* thisPtr, void* textUnit, unsigned int maxUnits, const char* text)
{
    if (!oSetMainText)
        return 0;

    if (IsArabicSafe())
    {
        void* nodeBefore = GetBodyTextNode(thisPtr);
        ForceNodeAlign(nodeBefore, TEXT_ALIGN_RIGHT);
    }

    const uint64_t result = oSetMainText(thisPtr, textUnit, maxUnits, text);

    if (!IsArabicSafe())
    {
        MirrorHeader(thisPtr, false);
        return result;
    }

    void* nodeAfter = GetBodyTextNode(thisPtr);
    ForceNodeAlign(nodeAfter, TEXT_ALIGN_RIGHT);
    MirrorHeader(thisPtr, true);
    return result;
}

bool InstallMbLogViewerBodyLayoutSetMainTextArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage = &RL_IsRightToLeft;

    gTargetSetMainText =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetMainText));
    if (gAddr.ModelNodeText_GetDisplayWidth)
        gGetDisplayWidth =
            reinterpret_cast<GetDisplayWidth_t>(ToRuntimeVA(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    if (gAddr.GetUixUtilityToFeedQuarkEnvironment)
        gGetUix = reinterpret_cast<GetUix_t>(ToRuntimeVA(hGame, gAddr.GetUixUtilityToFeedQuarkEnvironment));

    if (!gTargetSetMainText)
    {
        Log("[MbLogViewerEv::BodyLayout::SetMainText] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetSetMainText,
            reinterpret_cast<void*>(&hkSetMainText),
            reinterpret_cast<void**>(&oSetMainText));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[MbLogViewerEv::BodyLayout::SetMainText] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetSetMainText);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[MbLogViewerEv::BodyLayout::SetMainText] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[MbLogViewerEv::BodyLayout::SetMainText] Hook enabled.\n");
    return true;
}

void RemoveMbLogViewerBodyLayoutSetMainTextArabicHook()
{
    if (gTargetSetMainText)
    {
        MH_DisableHook(gTargetSetMainText);
        MH_RemoveHook(gTargetSetMainText);
        gTargetSetMainText = nullptr;
    }

    oSetMainText = nullptr;
    gIsArabLanguage = nullptr;
    gGetDisplayWidth = nullptr;
    gGetUix = nullptr;
    gAuthoredNext = 0;
    for (AuthoredNode& entry : gAuthored)
        entry = {};
    gHeaderLogged = false;
}