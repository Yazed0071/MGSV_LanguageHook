// ShowTextureLogo_ArabicLogoFix.cpp
//
// Hooks tpp::ui::UiCommand::ShowTextureLogo and injects an Arabic branch
// for the special logo selector that already has branches for
// JPN / ENG / FRA / ITA / DEU / SPA / POR / RUS / CHI / KOR.
//
// What this does:
// - If current language is Arabic
// - And arg1 resolves to the special logo key hash 0x11DDD3046B4C
// - Then it calls CommonDataManager::SetDispTextureLogo with the
//   Arabic texture hash 0x1568189A5584EE66 and style 0x887C9A23
// - Otherwise it falls back to the original ShowTextureLogo unchanged

#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"

// ------------------------------------------------------------
// Minimal Lua forward declarations
// ------------------------------------------------------------

// Forward declaration for the game's Lua state type.
// Params:
// - none
struct lua_State;

// Matches Lua's numeric type used by lua_tonumber.
// Params:
// - none
using lua_Number = double;

// ------------------------------------------------------------
// Address constants
// ------------------------------------------------------------

// Converts IDA absolute VAs into runtime addresses.
// Params:
// - none
static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

// Function addresses used by this hook.
// Params:
// - none
static constexpr uintptr_t ABS_ShowTextureLogo = 0x1408DFFB0ull;
static constexpr uintptr_t ABS_CommonDataManager_GetInstance = 0x140865D00ull;
static constexpr uintptr_t ABS_CommonDataManager_SetDispLogo = 0x140867330ull;
static constexpr uintptr_t ABS_GetStringId = 0x1409137A0ull;
static constexpr uintptr_t ABS_LuaCheckGlueString = 0x1400F1D50ull;
static constexpr uintptr_t ABS_LuaToGlueString = 0x1400F21D0ull;
static constexpr uintptr_t ABS_lua_isstring = 0x141A116B0ull;
static constexpr uintptr_t ABS_lua_isnumber = 0x141A11680ull;
static constexpr uintptr_t ABS_lua_tonumber = 0x141A12460ull;
static constexpr uintptr_t ABS_IsArabLanguage = 0x145F134E0ull;

// Special key/hash constants used by ShowTextureLogo.
// Params:
// - none
static constexpr uint64_t SPECIAL_LOGO_KEY_ID_48 = 0x11DDD3046B4Cull;
static constexpr uint64_t ARABIC_LOGO_TEXTURE_ID = 0x1568189A5584EE66ull;
static constexpr uint32_t SPECIAL_STYLE_ID = 0x887C9A23u;

// ------------------------------------------------------------
// Function pointer typedefs
// ------------------------------------------------------------

// Hook target: tpp::ui::UiCommand::ShowTextureLogo.
// Params:
// - L: lua_State*
using ShowTextureLogo_t = int(*)(lua_State* L);

// Current language helper from your sample.
// Params:
// - none
using IsArabLanguage_t = bool(__cdecl*)();

// tpp::ui::hud::CommonDataManager::GetInstance.
// Params:
// - none
using CommonDataManager_GetInstance_t = void* (__fastcall*)();

// tpp::ui::hud::CommonDataManager::SetDispTextureLogo.
// Params:
// - commonDataMgr: manager instance
// - showFlag: 1 to show
// - logoStrPtr: source string pointer or 0
// - timeSeconds: display time
// - texturePathId: texture path/hash id
// - styleId: style/string id
using CommonDataManager_SetDispLogo_t = void(__fastcall*)(
    void* commonDataMgr,
    uint8_t   showFlag,
    uint64_t  logoStrPtr,
    float     timeSeconds,
    uint64_t  texturePathId,
    uint32_t  styleId
    );

// tpp::ui::utility::GetStringId.
// Params:
// - outId: receives id/hash
// - cstr: source string
using GetStringId_t = uint64_t * (__fastcall*)(uint64_t* outId, const char* cstr);

// fox::LuaCheckGlueString.
// Params:
// - tempBuf: glue temp
// - L: lua_State*
// - index: lua stack index
using LuaCheckGlueString_t = void* (__fastcall*)(void* tempBuf, lua_State* L, int index);

// fox::LuaToGlueString.
// Params:
// - tempBuf: glue temp
// - L: lua_State*
// - index: lua stack index
// - allowNil: usually 0 here
using LuaToGlueString_t = void* (__fastcall*)(void* tempBuf, lua_State* L, int index, int allowNil);

// lua_isstring.
// Params:
// - L: lua_State*
// - index: lua stack index
using lua_isstring_t = int(__cdecl*)(lua_State* L, int index);

// lua_isnumber.
// Params:
// - L: lua_State*
// - index: lua stack index
using lua_isnumber_t = int(__cdecl*)(lua_State* L, int index);

// lua_tonumber.
// Params:
// - L: lua_State*
// - index: lua stack index
using lua_tonumber_t = lua_Number(__cdecl*)(lua_State* L, int index);

// ------------------------------------------------------------
// Globals
// ------------------------------------------------------------

// Original trampoline.
// Params:
// - none
static ShowTextureLogo_t oShowTextureLogo = nullptr;

// Resolved helper pointers.
// Params:
// - none
static IsArabLanguage_t                  gIsArabLanguage = nullptr;
static CommonDataManager_GetInstance_t   gCommonDataManagerGetInstance = nullptr;
static CommonDataManager_SetDispLogo_t   gSetDispTextureLogo = nullptr;
static GetStringId_t                     gGetStringId = nullptr;
static LuaCheckGlueString_t              gLuaCheckGlueString = nullptr;
static LuaToGlueString_t                 gLuaToGlueString = nullptr;
static lua_isstring_t                    gLuaIsString = nullptr;
static lua_isnumber_t                    gLuaIsNumber = nullptr;
static lua_tonumber_t                    gLuaToNumber = nullptr;

// Hook target storage.
// Params:
// - none
static void* gTargetShowTextureLogo = nullptr;

// ------------------------------------------------------------
// Function: ToRuntimeVA
// Converts an IDA absolute VA into a runtime VA using the game module.
// Params:
// - hGame: game module base
// - absVa: IDA absolute VA
// Returns:
// - runtime pointer
// ------------------------------------------------------------

static void* ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE));
}

// ------------------------------------------------------------
// Function: IsArabicSafe
// Calls the game's Arabic-language helper with SEH protection.
// Params:
// - none
// Returns:
// - true if current language is Arabic
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: ReadGlueStringPointer
// Reads the first qword from a glue-string object returned by the game.
// Params:
// - glueObj: returned object from LuaCheckGlueString / LuaToGlueString
// Returns:
// - raw C-string pointer as uint64_t, or 0
// ------------------------------------------------------------

static uint64_t ReadGlueStringPointer(void* glueObj)
{
    if (!glueObj)
        return 0;

    __try
    {
        return *reinterpret_cast<uint64_t*>(glueObj);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

// ------------------------------------------------------------
// Function: ResolveLuaArg1StringPtr
// Resolves arg1 exactly the same way ShowTextureLogo does.
// Params:
// - L: lua_State*
// Returns:
// - raw string pointer, or 0
// ------------------------------------------------------------

static uint64_t ResolveLuaArg1StringPtr(lua_State* L)
{
    if (!L || !gLuaIsString || !gLuaCheckGlueString)
        return 0;

    if (gLuaIsString(L, 1) == 0)
        return 0;

    unsigned char local48[24] = {};
    void* glueObj = gLuaCheckGlueString(local48, L, 1);
    return ReadGlueStringPointer(glueObj);
}

// ------------------------------------------------------------
// Function: ResolveLuaArg2TimeSeconds
// Resolves arg2 exactly the same way ShowTextureLogo does.
// Params:
// - L: lua_State*
// Returns:
// - float display time
// ------------------------------------------------------------

static float ResolveLuaArg2TimeSeconds(lua_State* L)
{
    if (!L || !gLuaIsNumber || !gLuaToNumber)
        return 0.0f;

    if (gLuaIsNumber(L, 2) == 0)
        return 0.0f;

    const lua_Number n = gLuaToNumber(L, 2);
    return static_cast<float>(n);
}

// ------------------------------------------------------------
// Function: ResolveLuaArg3StyleId
// Resolves arg3 exactly the same way ShowTextureLogo does.
// Params:
// - L: lua_State*
// Returns:
// - style/string id, or 0
// ------------------------------------------------------------

static uint32_t ResolveLuaArg3StyleId(lua_State* L)
{
    if (!L || !gLuaIsString || !gLuaToGlueString || !gGetStringId)
        return 0;

    if (gLuaIsString(L, 3) == 0)
        return 0;

    unsigned char local30[40] = {};
    void* glueObj = gLuaToGlueString(local30, L, 3, 0);
    const uint64_t strPtr = ReadGlueStringPointer(glueObj);
    if (strPtr == 0)
        return 0;

    uint64_t outId = 0;
    gGetStringId(&outId, reinterpret_cast<const char*>(strPtr));
    return static_cast<uint32_t>(outId);
}

// ------------------------------------------------------------
// Function: IsSpecialLogoRequest
// Checks whether arg1 resolves to the special ShowTextureLogo key that
// triggers the built-in language-specific logo selection ladder.
// Params:
// - rawLogoStrPtr: arg1 resolved C-string pointer
// Returns:
// - true if arg1 is the special logo key
// ------------------------------------------------------------

static bool IsSpecialLogoRequest(uint64_t rawLogoStrPtr)
{
    if (rawLogoStrPtr == 0 || !gGetStringId)
        return false;

    uint64_t outId = 0;
    gGetStringId(&outId, reinterpret_cast<const char*>(rawLogoStrPtr));

    return (outId & 0xFFFFFFFFFFFFull) == SPECIAL_LOGO_KEY_ID_48;
}

// ------------------------------------------------------------
// Function: CanHandleArabicSpecialCase
// Checks whether this call is the Arabic special-logo case we want to
// override ourselves.
// Params:
// - L: lua_State*
// - outLogoStrPtr: receives resolved arg1 pointer
// - outTimeSeconds: receives resolved arg2 float
// Returns:
// - true if the detour should handle the call directly
// ------------------------------------------------------------

static bool CanHandleArabicSpecialCase(
    lua_State* L,
    uint64_t& outLogoStrPtr,
    float& outTimeSeconds)
{
    outLogoStrPtr = 0;
    outTimeSeconds = 0.0f;

    if (!IsArabicSafe())
        return false;

    outLogoStrPtr = ResolveLuaArg1StringPtr(L);
    if (outLogoStrPtr == 0)
        return false;

    if (!IsSpecialLogoRequest(outLogoStrPtr))
        return false;

    outTimeSeconds = ResolveLuaArg2TimeSeconds(L);
    return true;
}

// ------------------------------------------------------------
// Function: hkShowTextureLogo
// Intercepts ShowTextureLogo. Only overrides the Arabic special-logo path.
// Everything else falls back to the original function unchanged.
// Params:
// - L: lua_State*
// Returns:
// - same int result as the original
// ------------------------------------------------------------

static int hkShowTextureLogo(lua_State* L)
{
    if (!oShowTextureLogo)
        return 0;

    uint64_t rawLogoStrPtr = 0;
    float timeSeconds = 0.0f;

    if (!CanHandleArabicSpecialCase(L, rawLogoStrPtr, timeSeconds))
        return oShowTextureLogo(L);

    if (!gCommonDataManagerGetInstance || !gSetDispTextureLogo)
        return oShowTextureLogo(L);

    void* commonDataMgr = gCommonDataManagerGetInstance();
    if (!commonDataMgr)
        return oShowTextureLogo(L);

    // Match the stock special-language path:
    // - force style id to 0x887C9A23
    // - force logoStrPtr to 0
    // - provide Arabic texture id
    gSetDispTextureLogo(
        commonDataMgr,
        1,
        0,
        timeSeconds,
        ARABIC_LOGO_TEXTURE_ID,
        SPECIAL_STYLE_ID);

    Log("[ShowTextureLogo] Arabic special logo applied. tex=0x%llX time=%f\n",
        static_cast<unsigned long long>(ARABIC_LOGO_TEXTURE_ID),
        timeSeconds);

    return 0;
}

// ------------------------------------------------------------
// Function: InstallShowTextureLogoArabicHook
// Resolves all helper functions, installs the ShowTextureLogo hook,
// and enables it.
// Params:
// - hGame: game module base
// Returns:
// - true on success
// ------------------------------------------------------------

bool InstallShowTextureLogoArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, ABS_IsArabLanguage));
    gCommonDataManagerGetInstance = reinterpret_cast<CommonDataManager_GetInstance_t>(ToRuntimeVA(hGame, ABS_CommonDataManager_GetInstance));
    gSetDispTextureLogo = reinterpret_cast<CommonDataManager_SetDispLogo_t>(ToRuntimeVA(hGame, ABS_CommonDataManager_SetDispLogo));
    gGetStringId = reinterpret_cast<GetStringId_t>(ToRuntimeVA(hGame, ABS_GetStringId));
    gLuaCheckGlueString = reinterpret_cast<LuaCheckGlueString_t>(ToRuntimeVA(hGame, ABS_LuaCheckGlueString));
    gLuaToGlueString = reinterpret_cast<LuaToGlueString_t>(ToRuntimeVA(hGame, ABS_LuaToGlueString));
    gLuaIsString = reinterpret_cast<lua_isstring_t>(ToRuntimeVA(hGame, ABS_lua_isstring));
    gLuaIsNumber = reinterpret_cast<lua_isnumber_t>(ToRuntimeVA(hGame, ABS_lua_isnumber));
    gLuaToNumber = reinterpret_cast<lua_tonumber_t>(ToRuntimeVA(hGame, ABS_lua_tonumber));

    gTargetShowTextureLogo = ToRuntimeVA(hGame, ABS_ShowTextureLogo);
    if (!gTargetShowTextureLogo)
        return false;

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetShowTextureLogo,
            reinterpret_cast<void*>(&hkShowTextureLogo),
            reinterpret_cast<void**>(&oShowTextureLogo));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[ShowTextureLogo] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetShowTextureLogo);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[ShowTextureLogo] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[ShowTextureLogo] Arabic logo hook enabled.\n");
    return true;
}

// ------------------------------------------------------------
// Function: RemoveShowTextureLogoArabicHook
// Disables and removes the ShowTextureLogo hook.
// Params:
// - none
// ------------------------------------------------------------

void RemoveShowTextureLogoArabicHook()
{
    if (gTargetShowTextureLogo)
    {
        MH_DisableHook(gTargetShowTextureLogo);
        MH_RemoveHook(gTargetShowTextureLogo);
        gTargetShowTextureLogo = nullptr;
    }

    oShowTextureLogo = nullptr;

    gIsArabLanguage = nullptr;
    gCommonDataManagerGetInstance = nullptr;
    gSetDispTextureLogo = nullptr;
    gGetStringId = nullptr;
    gLuaCheckGlueString = nullptr;
    gLuaToGlueString = nullptr;
    gLuaIsString = nullptr;
    gLuaIsNumber = nullptr;
    gLuaToNumber = nullptr;

    Log("[ShowTextureLogo] Arabic logo hook removed.\n");
}