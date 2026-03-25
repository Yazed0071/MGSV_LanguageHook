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

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static TipsLayoutController_SetPageText_t gOrigSetPageText = nullptr;
    static void* gTarget = nullptr;

    static constexpr ptrdiff_t kTitleNodeOffset = 0x18;
    static constexpr ptrdiff_t kBodyNodeOffset = 0x20;
    static constexpr ptrdiff_t kModelNodeTextAlignmentOffset = 0xD8;

    static constexpr uint32_t kArabicRightAlignment = 2;
}

/* Checks Arabic state safely. Parameters: none. */
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

/* Safely reads a bounded c-string. Parameters: src = source string, maxLen = maximum bytes, out = destination string. */
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

/* Safely writes a bounded c-string. Parameters: dst = destination buffer, dstSize = buffer size, src = source text. */
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

/* Safely reads a 32-bit field. Parameters: src = source address, outValue = returned value. */
static bool SafeReadU32(const void* src, uint32_t& outValue)
{
    __try
    {
        if (!src)
            return false;

        outValue = *reinterpret_cast<const uint32_t*>(src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        outValue = 0;
        return false;
    }
}

/* Safely writes a 32-bit field. Parameters: dst = destination address, value = value to write. */
static bool SafeWriteU32(void* dst, uint32_t value)
{
    __try
    {
        if (!dst)
            return false;

        *reinterpret_cast<uint32_t*>(dst) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Removes one trailing space before the page suffix. Parameters: s = source title string. */
static std::string TrimRightOneSpace(const std::string& s)
{
    if (!s.empty() && s.back() == ' ')
        return s.substr(0, s.size() - 1);

    return s;
}

/* Checks whether the title ends with a page suffix like "(1/5)". Parameters: text = title buffer text. */
static bool HasPageCounterSuffix(const char* text)
{
    if (!text || !*text)
        return false;

    const char* open = std::strrchr(text, '(');
    if (!open)
        return false;

    int currentPage = 0;
    int totalPages = 0;
    return sscanf_s(open, "(%d/%d)", &currentPage, &totalPages) == 2;
}

/* Rewrites "Title (1/5)" into "(5/1) Title". Parameters: src = original built title. */
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

    char rebuilt[128] = {};
    _snprintf_s(rebuilt, sizeof(rebuilt), _TRUNCATE, "(%d/%d) %s", totalPages, currentPage, title.c_str());
    return std::string(rebuilt);
}

/* Rewrites the already-built title buffer in the controller. Parameters: thisPtr = TipsLayoutController instance. */
static void ApplyArabicTipsPageTitleFix(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* titleBuf = reinterpret_cast<char*>(base + 0x6A);

    std::string before;
    if (!SafeReadCString(titleBuf, 100, before))
        return;

    if (!HasPageCounterSuffix(before.c_str()))
        return;

    const std::string after = RewriteTipsPageTitleArabic(before);
    if (after == before)
        return;

    if (!SafeWriteCString(titleBuf, 100, after.c_str()))
        return;

    Log("[TipsLayoutController::SetPageText] before: %s\n", before.c_str());
    Log("[TipsLayoutController::SetPageText] after : %s\n", after.c_str());
}

/* Gets a model node pointer from the controller. Parameters: thisPtr = controller, offset = field offset. */
static void* GetNodePtr(void* thisPtr, ptrdiff_t offset)
{
    if (!thisPtr)
        return nullptr;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);
        return *reinterpret_cast<void**>(base + offset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
}

/* Gets the alignment field address from a ModelNodeText. Parameters: modelNode = node pointer. */
static void* GetAlignmentFieldPtr(void* modelNode)
{
    if (!modelNode)
        return nullptr;

    return reinterpret_cast<uint8_t*>(modelNode) + kModelNodeTextAlignmentOffset;
}

/* Temporarily sets body alignment so CreateBoxText inside SetPageText uses RTL alignment. Parameters: thisPtr = controller, oldValue = saved old alignment, changed = whether write succeeded. */
static void BeginTemporaryBodyAlignment(void* thisPtr, uint32_t& oldValue, bool& changed)
{
    changed = false;
    oldValue = 0;

    void* bodyNode = GetNodePtr(thisPtr, kBodyNodeOffset);
    void* alignField = GetAlignmentFieldPtr(bodyNode);
    if (!alignField)
        return;

    if (!SafeReadU32(alignField, oldValue))
        return;

    if (!SafeWriteU32(alignField, kArabicRightAlignment))
        return;

    changed = true;
}

/* Restores the original body alignment after SetPageText finishes. Parameters: thisPtr = controller, oldValue = saved alignment, changed = whether restore is needed. */
static void EndTemporaryBodyAlignment(void* thisPtr, uint32_t oldValue, bool changed)
{
    if (!changed)
        return;

    void* bodyNode = GetNodePtr(thisPtr, kBodyNodeOffset);
    void* alignField = GetAlignmentFieldPtr(bodyNode);
    if (!alignField)
        return;

    SafeWriteU32(alignField, oldValue);
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

    if (!IsArabicSafe() || !thisPtr)
        return gOrigSetPageText(thisPtr, titleTextUnit, bodyTextUnit, bodyParam);

    uint32_t oldBodyAlignment = 0;
    bool bodyAlignmentChanged = false;

    // Important:
    // Set the body node alignment BEFORE the original function runs,
    // so the original CreateBoxText call uses RTL alignment.
    BeginTemporaryBodyAlignment(thisPtr, oldBodyAlignment, bodyAlignmentChanged);

    const uint64_t result = gOrigSetPageText(thisPtr, titleTextUnit, bodyTextUnit, bodyParam);

    // Restore immediately so the node does not stay permanently modified.
    EndTemporaryBodyAlignment(thisPtr, oldBodyAlignment, bodyAlignmentChanged);

    // Title fix can safely happen after the original builds the title buffer.
    ApplyArabicTipsPageTitleFix(thisPtr);

    return result;
}

/* Installs the TipsLayoutController::SetPageText Arabic hook. Parameters: hGame = game module handle. */
bool InstallTipsLayoutControllerSetPageTextHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.SetPageText)
    {
        Log("[TipsLayoutController::SetPageText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.SetPageText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkTipsLayoutController_SetPageText,
        reinterpret_cast<LPVOID*>(&gOrigSetPageText)) != MH_OK)
    {
        Log("[TipsLayoutController::SetPageText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[TipsLayoutController::SetPageText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[TipsLayoutController::SetPageText] Arabic hook enabled.\n");
    return true;
}

/* Removes the TipsLayoutController::SetPageText Arabic hook. Parameters: none. */
void RemoveTipsLayoutControllerSetPageTextHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigSetPageText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[TipsLayoutController::SetPageText] Arabic hook removed.\n");
}