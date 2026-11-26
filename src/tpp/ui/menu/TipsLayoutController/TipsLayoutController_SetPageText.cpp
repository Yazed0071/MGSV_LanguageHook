#include "pch.h"
#include <Windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <string>
#include <cstdio>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

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
    static constexpr size_t    kFullTitleSize = 1024;
    static constexpr uintptr_t kImageBase = 0x140000000ull;

    using FoxVsnprintf_t = int(__cdecl*)(char* buf, size_t size, const char* fmt, va_list args);

    static const uint8_t kFoxSnprintfPrologue[] = {
        0x4C, 0x89, 0x44, 0x24, 0x18, 0x4C, 0x89, 0x4C, 0x24, 0x20, 0x53, 0x57, 0x48, 0x83, 0xEC, 0x28,
    };

    static FoxVsnprintf_t gFoxVsnprintf = nullptr;
    static void* gFoxSnprintfTarget = nullptr;
    static void* gFoxSnprintfOriginal = nullptr;
    static thread_local char* tTitleBuf = nullptr;
    static thread_local std::string tFullTitle;
    static std::string gShownTitle;
}

static bool IsArabicSafe();
bool FormatArabicTimeLargestUnitFirst(char* buf, size_t size, const char* fmt, va_list args, int& written);

static bool IsPlayTimeFormat(const char* fmt)
{
    static const char* const kPlayTimeFormats[] = {
        "%02u:%02u/%02u:%02u",
        "%02u:%02u/--:--",
        "%02u:%02u:%02u/%02u:%02u:%02u",
        "%02u:%02u:%02u/--:--:--",
    };
    if (fmt[0] != '%' || fmt[1] != '0' || fmt[2] != '2' || fmt[3] != 'u')
        return false;
    for (const char* known : kPlayTimeFormats)
    {
        if (std::strcmp(fmt, known) == 0)
            return true;
    }
    return false;
}

static void PutTotalTimeFirst(char* buf, size_t size)
{
    const size_t length = strnlen(buf, size);
    const char* slash = static_cast<const char*>(std::memchr(buf, '/', length));
    if (!slash || length >= 64)
        return;
    const size_t left = static_cast<size_t>(slash - buf);
    char swapped[64];
    std::memcpy(swapped, slash + 1, length - left - 1);
    swapped[length - left - 1] = '/';
    std::memcpy(swapped + length - left, buf, left);
    std::memcpy(buf, swapped, length);
}

static int __cdecl hkFoxSnprintf(char* buf, size_t size, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int timeWritten = 0;
    if (FormatArabicTimeLargestUnitFirst(buf, size, fmt, args, timeWritten))
    {
        va_end(args);
        return timeWritten;
    }
    va_list again;
    va_copy(again, args);
    const int written = gFoxVsnprintf(buf, size, fmt, args);
    va_end(args);
    if (tTitleBuf && buf == tTitleBuf && fmt && (written < 0 || static_cast<size_t>(written) >= size))
    {
        static thread_local char full[kFullTitleSize];
        const int needed = gFoxVsnprintf(full, sizeof(full), fmt, again);
        if (needed > 0 && static_cast<size_t>(needed) < sizeof(full))
            tFullTitle.assign(full, static_cast<size_t>(needed));
    }
    va_end(again);
    if (written > 0 && static_cast<size_t>(written) < size && buf && fmt && IsPlayTimeFormat(fmt) && IsArabicSafe())
        PutTotalTimeFirst(buf, size);
    return written;
}

static bool CodeMatches(const void* target, const uint8_t* expected, size_t size)
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

void KeepArabicLinesRightAligned(void* node);

/* Forces one ModelNodeText to right alignment. */
static void ForceRightAlignNode(void* node)
{
    if (!node)
        return;

    SafeWriteU8(reinterpret_cast<uint8_t*>(node) + kAlignOffset, TEXT_ALIGN_RIGHT);
    KeepArabicLinesRightAligned(node);
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

    char rebuilt[kFullTitleSize] = {};
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
static void RefreshArabicTitle(void* thisPtr, void* titleTextUnit, const std::string& fullTitle)
{
    if (!thisPtr || !gSetTextForModelNodeText)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* titleBuf = reinterpret_cast<char*>(base + kTitleBufOffset);

    std::string before = fullTitle;
    if (before.empty() && !SafeReadCString(titleBuf, kTitleBufSize, before))
        return;

    const std::string after = RewriteTipsPageTitleArabic(before);
    if (after.empty() || (after == before && fullTitle.empty()))
        return;

    if (after.size() < kTitleBufSize && !SafeWriteCString(titleBuf, kTitleBufSize, after.c_str()))
        return;

    void* titleNode = GetNodePtr(thisPtr, kTitleNodeOffset);
    if (!titleNode)
        return;

    gShownTitle = after;
    ForceRightAlignNode(titleNode);
    gSetTextForModelNodeText(titleNode, titleTextUnit, gShownTitle.c_str(), 1);
    ForceRightAlignNode(titleNode);
    if (!fullTitle.empty())
        Log("[TipsLayoutController::SetPageText] title did not fit the game's %zu-byte buffer - shown in full (%zu bytes)\n",
            kTitleBufSize, fullTitle.size());

    LogDetail("[TipsLayoutController::SetPageText] before: %s\n", before.c_str());
    LogDetail("[TipsLayoutController::SetPageText] after : %s\n", after.c_str());
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

    tFullTitle.clear();
    tTitleBuf = thisPtr ? reinterpret_cast<char*>(thisPtr) + kTitleBufOffset : nullptr;
    const uint64_t result =
        gOrigSetPageText(thisPtr, titleTextUnit, bodyTextUnit, bodyParam);
    tTitleBuf = nullptr;
    const std::string fullTitle = std::move(tFullTitle);
    tFullTitle.clear();

    if (!IsArabicSafe() || !thisPtr)
        return result;

    void* titleNode = GetNodePtr(thisPtr, kTitleNodeOffset);
    void* bodyNode = GetNodePtr(thisPtr, kBodyNodeOffset);

    // Important:
    // Do NOT restore here.
    // For this target, we want these nodes to stay RTL in Arabic.
    ForceRightAlignNode(titleNode);
    ForceRightAlignNode(bodyNode);

    RefreshArabicTitle(thisPtr, titleTextUnit, fullTitle);

    return result;
}

/* Installs the TipsLayoutController::SetPageText Arabic hook. */
bool InstallTipsLayoutControllerSetPageTextHook(HMODULE hGame)
{
    if (!gAddr.IsArabLanguage || !gAddr.SetPageText || !gAddr.SetTextForModelNodeText)
    {
        Log("[TipsLayoutController::SetPageText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
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

    if (!hGame || !gAddr.FoxSnprintf || !gAddr.FoxVsnprintf)
    {
        Log("[fox::snprintf] address missing - long Arabic tip titles stay cut at %zu bytes.\n", kTitleBufSize);
        return true;
    }
    void* snprintfTarget =
        reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (gAddr.FoxSnprintf - kImageBase));
    if (!CodeMatches(snprintfTarget, kFoxSnprintfPrologue, sizeof(kFoxSnprintfPrologue)))
    {
        Log("[fox::snprintf] code is not what this build should have - long Arabic tip titles stay cut.\n");
        return true;
    }
    gFoxVsnprintf = reinterpret_cast<FoxVsnprintf_t>(
        reinterpret_cast<uintptr_t>(hGame) + (gAddr.FoxVsnprintf - kImageBase));
    if (MH_CreateHook(snprintfTarget, reinterpret_cast<void*>(&hkFoxSnprintf), &gFoxSnprintfOriginal) != MH_OK ||
        MH_EnableHook(snprintfTarget) != MH_OK)
    {
        MH_RemoveHook(snprintfTarget);
        gFoxVsnprintf = nullptr;
        Log("[fox::snprintf] hook failed - long Arabic tip titles stay cut.\n");
        return true;
    }
    gFoxSnprintfTarget = snprintfTarget;
    Log("[fox::snprintf] watched while TIPS titles are formatted - long Arabic titles are shown in full.\n");
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

    if (gFoxSnprintfTarget)
    {
        MH_DisableHook(gFoxSnprintfTarget);
        MH_RemoveHook(gFoxSnprintfTarget);
        gFoxSnprintfTarget = nullptr;
    }
    gFoxSnprintfOriginal = nullptr;
    gFoxVsnprintf = nullptr;

    gOrigSetPageText = nullptr;
    gSetTextForModelNodeText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[TipsLayoutController::SetPageText] Arabic hook removed.\n");
}