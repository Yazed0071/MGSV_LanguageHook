// GameLangState_PersistExtended.cpp
//
// Fixes extended language ids (especially 9/10) so they:
// - work at runtime
// - survive restarting the game
//
// Replaces your previous GameLangState_KeepCJK.cpp.
//
// Hooks:
// - getter  : FUN_146084A80  -> reads current lang from +0x39D0
// - setter  : FUN_14094E950  -> writes current lang to +0x39D0
//
// Persistence:
// - writes selected lang id to an INI next to your DLL
// - restores it on boot through the getter hook

#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include "MinHook.h"
#include "log.h"

// ------------------------------------------------------------
// Address constants
// ------------------------------------------------------------

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uintptr_t ABS_GetGameLanguageState = 0x146084A80ull; // returns *(u32*)(this+0x39D0)
static constexpr uintptr_t ABS_SetGameLanguageState = 0x14094E950ull; // writes lang state
static constexpr uintptr_t ABS_GameConfigGetInstance = 0x14052F9C0ull;

// ------------------------------------------------------------
// Globals
// ------------------------------------------------------------

using GetGameLanguageState_t = uint32_t(__fastcall*)(void* thisPtr);
using SetGameLanguageState_t = void(__fastcall*)(void* thisPtr, uint32_t langId);
using GameConfigGetInstance_t = void* (__fastcall*)();

static GetGameLanguageState_t  oGetGameLanguageState = nullptr;
static SetGameLanguageState_t  oSetGameLanguageState = nullptr;
static GameConfigGetInstance_t gGameConfigGetInstance = nullptr;

static void* gTargetGetGameLanguageState = nullptr;
static void* gTargetSetGameLanguageState = nullptr;

static bool     gPersistLoaded = false;
static uint32_t gPersistedLang = 0;

// ------------------------------------------------------------
// Address helper
// Converts an IDA absolute VA into runtime VA.
// Params:
// - hGame: base module handle for mgsvtpp.exe
// - absVa: IDA absolute VA
// Returns:
// - runtime VA
// ------------------------------------------------------------

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

// ------------------------------------------------------------
// Vtable helper
// Reads a typed virtual function by byte offset.
// Params:
// - obj: object instance
// - byteOffset: vtable byte offset, for example 0x180
// Returns:
// - typed function pointer or nullptr
// ------------------------------------------------------------

template <typename T>
static T GetVFunc(void* obj, size_t byteOffset)
{
    if (!obj)
        return nullptr;

    auto*** p = reinterpret_cast<void***>(obj);
    if (!p || !*p)
        return nullptr;

    return reinterpret_cast<T>((*p)[byteOffset / sizeof(void*)]);
}

// ------------------------------------------------------------
// Path helper
// Builds the INI path next to this DLL.
// Params:
// - outPath: destination buffer
// - outPathCount: buffer size in chars
// Returns:
// - true on success
// ------------------------------------------------------------

static bool BuildIniPath(char* outPath, size_t outPathCount)
{
    if (!outPath || outPathCount == 0)
        return false;

    HMODULE hSelf = nullptr;
    if (!GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&BuildIniPath),
        &hSelf))
    {
        return false;
    }

    char dllPath[MAX_PATH] = {};
    if (!GetModuleFileNameA(hSelf, dllPath, MAX_PATH))
        return false;

    char* slash = strrchr(dllPath, '\\');
    if (!slash)
        return false;

    *(slash + 1) = '\0';

    const int wrote = snprintf(outPath, outPathCount, "%s%s", dllPath, "MGSV_ExtendedLanguage.ini");
    return (wrote > 0 && static_cast<size_t>(wrote) < outPathCount);
}

// ------------------------------------------------------------
// Validation helper
// Checks whether a lang id is one we want to persist/restore.
// Params:
// - langId: candidate language id
// Returns:
// - true if valid
// Notes:
// - 0..10 matches the ids you are using right now
// ------------------------------------------------------------

static bool IsValidExtendedLang(uint32_t langId)
{
    return langId <= 10;
}

// ------------------------------------------------------------
// INI load helper
// Loads the persisted lang id from disk.
// Params:
// - outLangId: receives persisted value if found
// Returns:
// - true if loaded successfully
// ------------------------------------------------------------

static bool LoadPersistedLangFromIni(uint32_t& outLangId)
{
    char iniPath[MAX_PATH] = {};
    if (!BuildIniPath(iniPath, MAX_PATH))
        return false;

    const UINT value = GetPrivateProfileIntA("Language", "SelectedLangId", 0xFFFFFFFFu, iniPath);
    if (value == 0xFFFFFFFFu)
        return false;

    if (!IsValidExtendedLang(value))
        return false;

    outLangId = value;
    return true;
}

// ------------------------------------------------------------
// INI save helper
// Saves the selected lang id to disk.
// Params:
// - langId: language id to persist
// Returns:
// - true on success
// ------------------------------------------------------------

static bool SavePersistedLangToIni(uint32_t langId)
{
    char iniPath[MAX_PATH] = {};
    if (!BuildIniPath(iniPath, MAX_PATH))
        return false;

    char valueBuf[32] = {};
    snprintf(valueBuf, sizeof(valueBuf), "%u", langId);

    return WritePrivateProfileStringA("Language", "SelectedLangId", valueBuf, iniPath) != FALSE;
}

// ------------------------------------------------------------
// Cache helper
// Loads persisted lang once into memory.
// Params:
// - none
// Returns:
// - none
// ------------------------------------------------------------

static void EnsurePersistLoaded()
{
    if (gPersistLoaded)
        return;

    uint32_t langId = 0;
    if (LoadPersistedLangFromIni(langId))
    {
        gPersistedLang = langId;
        Log("[GameLangState] Loaded persisted langId=%u\n", gPersistedLang);
    }

    gPersistLoaded = true;
}

// ------------------------------------------------------------
// GameConfig notify helper
// Forwards the selected lang byte to GameConfig, matching original intent.
// Params:
// - langId: language id to send
// Returns:
// - none
// ------------------------------------------------------------

static void NotifyGameConfig(uint32_t langId)
{
    if (!gGameConfigGetInstance)
        return;

    void* gameConfig = gGameConfigGetInstance();
    if (!gameConfig)
        return;

    using Fn = void(__fastcall*)(void* thisPtr, uint32_t langByte);
    Fn fn = GetVFunc<Fn>(gameConfig, 0x180);
    if (!fn)
        return;

    fn(gameConfig, (langId & 0xFF));
}

// ------------------------------------------------------------
// Field helper
// Reads current language from object storage.
// Params:
// - thisPtr: target object
// Returns:
// - current +0x39D0 value, or 0 if invalid
// ------------------------------------------------------------

static uint32_t ReadCurrentLangField(void* thisPtr)
{
    if (!thisPtr)
        return 0;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    return *reinterpret_cast<uint32_t*>(base + 0x39D0);
}

// ------------------------------------------------------------
// Field helper
// Writes language state into the object's storage.
// Params:
// - thisPtr: target object
// - langId: new current language
// Returns:
// - none
// Notes:
// - +0x39D4 gets previous value
// - +0x39D0 gets new value
// ------------------------------------------------------------

static void WriteCurrentLangField(void* thisPtr, uint32_t langId)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    const uint32_t oldLang = *reinterpret_cast<uint32_t*>(base + 0x39D0);
    *reinterpret_cast<uint32_t*>(base + 0x39D4) = oldLang;
    *reinterpret_cast<uint32_t*>(base + 0x39D0) = langId;
}

// ------------------------------------------------------------
// Persistence update helper
// Updates memory cache and INI file for a selected language.
// Params:
// - langId: selected language id
// Returns:
// - none
// ------------------------------------------------------------

static void UpdatePersistence(uint32_t langId)
{
    if (!IsValidExtendedLang(langId))
        return;

    gPersistedLang = langId;
    gPersistLoaded = true;

    if (SavePersistedLangToIni(langId))
        Log("[GameLangState] Persisted langId=%u\n", langId);
    else
        Log("[GameLangState] Failed to persist langId=%u\n", langId);
}

// ------------------------------------------------------------
// Hook: getter
// Restores persisted language on boot by overriding +0x39D0 when needed.
// Params:
// - thisPtr: language-state owner object
// Returns:
// - active language id
// ------------------------------------------------------------

static uint32_t __fastcall hkGetGameLanguageState(void* thisPtr)
{
    const uint32_t current = ReadCurrentLangField(thisPtr);

    EnsurePersistLoaded();

    if (gPersistLoaded && IsValidExtendedLang(gPersistedLang) && gPersistedLang != current)
    {
        WriteCurrentLangField(thisPtr, gPersistedLang);
        NotifyGameConfig(gPersistedLang);

        Log("[GameLangState::Get] restored persisted langId=%u (was %u)\n", gPersistedLang, current);
        return gPersistedLang;
    }

    return current;
}

// ------------------------------------------------------------
// Hook: setter
// Keeps 9/10 from collapsing to 0 and persists all selected ids.
// Params:
// - thisPtr: language-state owner object
// - langId: requested language id
// Returns:
// - none
// ------------------------------------------------------------

static void __fastcall hkSetGameLanguageState(void* thisPtr, uint32_t langId)
{
    UpdatePersistence(langId);

    // For stock ids, let the original do its normal work.
    if (langId < 9)
    {
        if (oSetGameLanguageState)
        {
            oSetGameLanguageState(thisPtr, langId);
            Log("[GameLangState::Set] stock langId=%u\n", langId);
            return;
        }

        WriteCurrentLangField(thisPtr, langId);
        NotifyGameConfig(langId);
        Log("[GameLangState::Set] stock fallback langId=%u\n", langId);
        return;
    }

    // Extended ids: do NOT let original clamp them to 0.
    WriteCurrentLangField(thisPtr, langId);
    NotifyGameConfig(langId);

    Log("[GameLangState::Set] extended langId=%u kept as-is\n", langId);
}

// ------------------------------------------------------------
// Hook helper
// Creates and enables one MinHook hook.
// Params:
// - target: target function address
// - detour: detour function
// - original: receives trampoline if wanted
// - name: debug label
// Returns:
// - true on success
// ------------------------------------------------------------

static bool CreateAndEnableHook(void* target, void* detour, void** original, const char* name)
{
    const MH_STATUS createSt = MH_CreateHook(target, detour, original);
    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[%s] MH_CreateHook failed: %d\n", name, static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(target);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[%s] MH_EnableHook failed: %d\n", name, static_cast<int>(enableSt));
        return false;
    }

    Log("[%s] Hook enabled.\n", name);
    return true;
}

bool InstallGameLangStateKeepCJKHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    EnsurePersistLoaded();

    gGameConfigGetInstance =
        reinterpret_cast<GameConfigGetInstance_t>(ToRuntimeVA(hGame, ABS_GameConfigGetInstance));

    gTargetGetGameLanguageState =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_GetGameLanguageState));

    gTargetSetGameLanguageState =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_SetGameLanguageState));

    if (!gTargetGetGameLanguageState || !gTargetSetGameLanguageState)
    {
        Log("[GameLangState] Failed to resolve getter/setter target.\n");
        return false;
    }

    if (!CreateAndEnableHook(
        gTargetGetGameLanguageState,
        reinterpret_cast<void*>(&hkGetGameLanguageState),
        reinterpret_cast<void**>(&oGetGameLanguageState),
        "GameLangState::Get"))
    {
        return false;
    }

    if (!CreateAndEnableHook(
        gTargetSetGameLanguageState,
        reinterpret_cast<void*>(&hkSetGameLanguageState),
        reinterpret_cast<void**>(&oSetGameLanguageState),
        "GameLangState::Set"))
    {
        return false;
    }

    Log("[GameLangState] Persistence hook pack installed.\n");
    return true;
}

// ------------------------------------------------------------
// Remove function
// Removes both hooks.
// Params:
// - none
// Returns:
// - none
// ------------------------------------------------------------

void RemoveGameLangStateKeepCJKHook()
{
    if (gTargetGetGameLanguageState)
    {
        MH_DisableHook(gTargetGetGameLanguageState);
        MH_RemoveHook(gTargetGetGameLanguageState);
        gTargetGetGameLanguageState = nullptr;
    }

    if (gTargetSetGameLanguageState)
    {
        MH_DisableHook(gTargetSetGameLanguageState);
        MH_RemoveHook(gTargetSetGameLanguageState);
        gTargetSetGameLanguageState = nullptr;
    }

    oGetGameLanguageState = nullptr;
    oSetGameLanguageState = nullptr;
    gGameConfigGetInstance = nullptr;

    Log("[GameLangState] Persistence hook pack removed.\n");
}