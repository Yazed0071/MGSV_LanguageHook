#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <cstdio>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using TipsLayoutController_SetPageText_t =
        uint64_t(__fastcall*)(void* thisPtr, void* titleTextUnit, void* bodyTextUnit, uint32_t bodyParam);

    using SetTextForModelNodeText_t =
        void(__fastcall*)(void* modelNodeText, void* textUnit, const char* text, uint8_t flag);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static TipsLayoutController_SetPageText_t gOrigSetPageText = nullptr;
    static SetTextForModelNodeText_t gSetTextForModelNodeText = nullptr;
    static void* gTarget = nullptr;

    static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

    static constexpr ptrdiff_t kTitleNodeOffset = 0x18;
    static constexpr ptrdiff_t kBodyNodeOffset = 0x20;
    static constexpr ptrdiff_t kAlignOffset = 0xD8;
    static constexpr ptrdiff_t kTitleBufOffset = 0x6A;
    static constexpr size_t    kTitleBufSize = 100;
}

/* Checks Arabic state safely. */
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

/* Safely reads a pointer. */
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

/* Safely writes one byte. */
static bool SafeWriteU8(void* addr, uint8_t value)
{
    __try
    {
        if (!addr)
            return false;

        *reinterpret_cast<uint8_t*>(addr) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Safely reads a bounded c-string. */
static bool SafeReadCString(const char* src, size_t maxLen, std::string& out)
{
    __try
    {
        if (!src || maxLen == 0)
        {
            out.clear();
            return false;
        }

        size_t len = 0;
        while (len < maxLen && src[len] != '\0')
            ++len;

        out.assign(src, len);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out.clear();
        return false;
    }
}

/* Safely writes a bounded c-string. */
static bool SafeWriteCString(char* dst, size_t dstSize, const char* src)
{
    __try
    {
        if (!dst || dstSize == 0)
            return false;

        if (!src)
        {
            dst[0] = '\0';
            return true;
        }

        _snprintf_s(dst, dstSize, _TRUNCATE, "%s", src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Gets a node pointer from the controller. */
static void* GetNodePtr(void* thisPtr, ptrdiff_t offset)
{
    if (!thisPtr)
        return nullptr;

    void* node = nullptr;
    SafeReadPtr(reinterpret_cast<uint8_t*>(thisPtr) + offset, node);
    return node;
}

/* Forces one ModelNodeText to right alignment. */
static void ForceRightAlignNode(void* node)
{
    if (!node)
        return;

    SafeWriteU8(reinterpret_cast<uint8_t*>(node) + kAlignOffset, TEXT_ALIGN_RIGHT);
}

/* Trims one trailing space before "(x/y)". */
static std::string TrimRightOneSpace(const std::string& s)
{
    if (!s.empty() && s.back() == ' ')
        return s.substr(0, s.size() - 1);

    return s;
}

/* Rewrites "Title (1/5)" into "(5/1) Title". */
static std::string RewriteTipsPageTitleArabic(const std::string& src)
{
    if (src.empty())
        return src;

    const size_t openPos = src.rfind('(');
    if (openPos == std::string::npos)
        return src;

    int currentPage = 0;
    int totalPages = 0;

    if (sscanf_s(src.c_str() + openPos, "(%d/%d)", &currentPage, &totalPages) != 2)
        return src;

    std::string title = src.substr(0, openPos);
    title = TrimRightOneSpace(title);

    if (title.empty())
        return src;

    char rebuilt[kTitleBufSize] = {};
    _snprintf_s(
        rebuilt,
        sizeof(rebuilt),
        _TRUNCATE,
        "(%d/%d) %s",
        totalPages,
        currentPage,
        title.c_str());

    return std::string(rebuilt);
}

/* Rewrites the title buffer and refreshes the title node. */
static void RefreshArabicTitle(void* thisPtr, void* titleTextUnit)
{
    if (!thisPtr || !gSetTextForModelNodeText)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* titleBuf = reinterpret_cast<char*>(base + kTitleBufOffset);

    std::string before;
    if (!SafeReadCString(titleBuf, kTitleBufSize, before))
        return;

    const std::string after = RewriteTipsPageTitleArabic(before);
    if (after.empty() || after == before)
        return;

    if (!SafeWriteCString(titleBuf, kTitleBufSize, after.c_str()))
        return;

    void* titleNode = GetNodePtr(thisPtr, kTitleNodeOffset);
    if (!titleNode)
        return;

    ForceRightAlignNode(titleNode);
    gSetTextForModelNodeText(titleNode, titleTextUnit, titleBuf, 1);
    ForceRightAlignNode(titleNode);

    Log("[TipsLayoutController::SetPageText] before: %s\n", before.c_str());
    Log("[TipsLayoutController::SetPageText] after : %s\n", after.c_str());
}

/* Hook for TipsLayoutController::SetPageText(this, titleTextUnit, bodyTextUnit, bodyParam). */
static uint64_t __fastcall hkTipsLayoutController_SetPageText(
    void* thisPtr,
    void* titleTextUnit,
    void* bodyTextUnit,
    uint32_t bodyParam)
{
    if (!gOrigSetPageText)
        return 0;

    const uint64_t result =
        gOrigSetPageText(thisPtr, titleTextUnit, bodyTextUnit, bodyParam);

    if (!IsArabicSafe() || !thisPtr)
        return result;

    void* titleNode = GetNodePtr(thisPtr, kTitleNodeOffset);
    void* bodyNode = GetNodePtr(thisPtr, kBodyNodeOffset);

    // Important:
    // Do NOT restore here.
    // For this target, we want these nodes to stay RTL in Arabic.
    ForceRightAlignNode(titleNode);
    ForceRightAlignNode(bodyNode);

    RefreshArabicTitle(thisPtr, titleTextUnit);

    return result;
}

/* Installs the TipsLayoutController::SetPageText Arabic hook. */
bool InstallTipsLayoutControllerSetPageTextHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.SetPageText || !gAddr.SetTextForModelNodeText)
    {
        Log("[TipsLayoutController::SetPageText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gSetTextForModelNodeText = reinterpret_cast<SetTextForModelNodeText_t>(gAddr.SetTextForModelNodeText);
    gTarget = reinterpret_cast<void*>(gAddr.SetPageText);

    if (!gTarget)
        return false;

    const MH_STATUS createSt =
        MH_CreateHook(
            gTarget,
            reinterpret_cast<void*>(&hkTipsLayoutController_SetPageText),
            reinterpret_cast<void**>(&gOrigSetPageText));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[TipsLayoutController::SetPageText] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTarget);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[TipsLayoutController::SetPageText] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[TipsLayoutController::SetPageText] Arabic hook enabled.\n");
    return true;
}

/* Removes the TipsLayoutController::SetPageText Arabic hook. */
void RemoveTipsLayoutControllerSetPageTextHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigSetPageText = nullptr;
    gSetTextForModelNodeText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[TipsLayoutController::SetPageText] Arabic hook removed.\n");
}