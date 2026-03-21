// ChapterTelop_GetFtexPathId_ArabicFix.cpp
//
// Arabic chapter telop texture fix.
//
// Why this hook point is enough:
// - ShowChapterTelop eventually calls ChapterTelopInfo::GetFtexPathId
// - ChapterTelopImpl::Update also calls ChapterTelopInfo::GetFtexPathId
// - This function is where the final per-language chapter FTEX is chosen
//
// Important:
// - This function MUST return the same pointer the original returns
// - The caller expects RAX to point to the output buffer and dereferences it
//
// Behavior:
// - If current language is Arabic, write Arabic chapter texture id into
//   *chapterTexture and return chapterTexture
// - Otherwise call the original function unchanged

#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"

// ------------------------------------------------------------
// External helpers
// ------------------------------------------------------------

// Function: current-language helper.
// Params:
// - none
using IsArabLanguage_t = bool(__cdecl*)();
static IsArabLanguage_t gIsArabLanguage = nullptr;

// From your working example.
// Params:
// - none
static constexpr uintptr_t ABS_IsArabLanguage = 0x145F134E0ull;

// ------------------------------------------------------------
// Address constants
// ------------------------------------------------------------

// Function: image base used by IDA absolute VAs.
// Params:
// - none
static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

// Function: target to hook.
// Params:
// - none
static constexpr uintptr_t ABS_ChapterTelopInfo_GetFtexPathId = 0x1408D05F0ull;

// ------------------------------------------------------------
// Arabic chapter texture ids
// ------------------------------------------------------------

// Function: Arabic chapter textures in the exact order you provided.
// Mapping here is by chapterCode 0..3.
// Params:
// - none
static constexpr uint64_t kArabicChapterTextureIds[4] =
{
    0x156A29CFCE9E441Bull, // code 0
    0x156BA1F26ECBDBD4ull, // code 1
    0x156A0FFB69549AAAull, // code 2
    0x15681FBE4CC91DFAull  // code 3
};

// ------------------------------------------------------------
// Game function typedefs
// ------------------------------------------------------------

// Function: original ChapterTelopInfo::GetFtexPathId.
// Params:
// - param1: original RCX passthrough
// - chapterTexture: output pointer
// - chapterCode: code 0..3, game clamps 4+ back to 0
// - language: original language code
// Returns:
// - same output pointer passed in chapterTexture
using GetFtexPathId_t = uint64_t * (__fastcall*)(
    void* param1,
    uint64_t* chapterTexture,
    uint8_t   chapterCode,
    int       language
    );

static GetFtexPathId_t oGetFtexPathId = nullptr;
static void* gTargetGetFtexPathId = nullptr;

// ------------------------------------------------------------
// Function: ToRuntimeVA
// Converts an IDA absolute VA into a runtime VA using the game module.
// Params:
// - hGame: game module base
// - absVa: IDA absolute VA
// Returns:
// - runtime VA
// ------------------------------------------------------------

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

// ------------------------------------------------------------
// Function: IsArabicSafe
// Calls the game's Arabic-language helper safely.
// Params:
// - none
// Returns:
// - true if current language is Arabic
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: SafeWriteU64
// Writes a uint64_t to memory with SEH protection.
// Params:
// - dst: destination pointer
// - value: value to write
// Returns:
// - true on success
// ------------------------------------------------------------

static bool SafeWriteU64(uint64_t* dst, uint64_t value)
{
    __try
    {
        if (!dst)
            return false;

        *dst = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

// ------------------------------------------------------------
// Function: GetArabicChapterTextureForCode
// Returns the Arabic chapter texture for a chapter code.
// The stock game clamps chapterCode > 3 back to 0, so we do the same.
// Params:
// - chapterCode: requested chapter code
// Returns:
// - Arabic texture path id
// ------------------------------------------------------------

static uint64_t GetArabicChapterTextureForCode(uint8_t chapterCode)
{
    if (chapterCode > 3)
        chapterCode = 0;

    return kArabicChapterTextureIds[chapterCode];
}

// ------------------------------------------------------------
// Function: hkGetFtexPathId
// Overrides chapter texture selection only when the current language
// is Arabic. Otherwise uses stock behavior.
// Params:
// - param1: original RCX passthrough
// - chapterTexture: output pointer
// - chapterCode: code 0..3
// - language: original language code
// Returns:
// - same pointer the caller passed in chapterTexture
// ------------------------------------------------------------

static uint64_t* __fastcall hkGetFtexPathId(
    void* param1,
    uint64_t* chapterTexture,
    uint8_t   chapterCode,
    int       language)
{
    if (!chapterTexture)
    {
        if (oGetFtexPathId)
            return oGetFtexPathId(param1, chapterTexture, chapterCode, language);

        return nullptr;
    }

    if (!IsArabicSafe())
    {
        if (oGetFtexPathId)
            return oGetFtexPathId(param1, chapterTexture, chapterCode, language);

        return chapterTexture;
    }

    const uint64_t arabicTexture = GetArabicChapterTextureForCode(chapterCode);
    if (!SafeWriteU64(chapterTexture, arabicTexture))
    {
        if (oGetFtexPathId)
            return oGetFtexPathId(param1, chapterTexture, chapterCode, language);

        return chapterTexture;
    }

    Log("[ChapterTelopInfo::GetFtexPathId] Arabic override applied. code=%u texture=0x%llX\n",
        static_cast<unsigned>(chapterCode),
        static_cast<unsigned long long>(arabicTexture));

    return chapterTexture;
}

// ------------------------------------------------------------
// Function: InstallChapterTelopArabicFtexHook
// Resolves helpers, creates the hook, and enables it.
// Params:
// - hGame: game module base
// Returns:
// - true on success
// ------------------------------------------------------------

bool InstallChapterTelopArabicFtexHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, ABS_IsArabLanguage));

    gTargetGetFtexPathId =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_ChapterTelopInfo_GetFtexPathId));

    if (!gTargetGetFtexPathId)
    {
        Log("[ChapterTelopInfo::GetFtexPathId] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetGetFtexPathId,
            reinterpret_cast<void*>(&hkGetFtexPathId),
            reinterpret_cast<void**>(&oGetFtexPathId));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[ChapterTelopInfo::GetFtexPathId] MH_CreateHook failed: %d\n",
            static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetGetFtexPathId);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[ChapterTelopInfo::GetFtexPathId] MH_EnableHook failed: %d\n",
            static_cast<int>(enableSt));
        return false;
    }

    Log("[ChapterTelopInfo::GetFtexPathId] Arabic chapter texture hook enabled.\n");
    return true;
}

// ------------------------------------------------------------
// Function: RemoveChapterTelopArabicFtexHook
// Disables and removes the hook.
// Params:
// - none
// ------------------------------------------------------------

void RemoveChapterTelopArabicFtexHook()
{
    if (gTargetGetFtexPathId)
    {
        MH_DisableHook(gTargetGetFtexPathId);
        MH_RemoveHook(gTargetGetFtexPathId);
        gTargetGetFtexPathId = nullptr;
    }

    oGetFtexPathId = nullptr;
    gIsArabLanguage = nullptr;

    Log("[ChapterTelopInfo::GetFtexPathId] Arabic chapter texture hook removed.\n");
}