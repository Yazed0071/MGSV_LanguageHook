#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <unordered_set>

#include "HookUtils.h"
#include "log.h"
#include "FoxHashes.h"
#include "AddressSet.h"

extern "C" {
    #include "lua.h"
    #include "lauxlib.h"
    #include "lualib.h"
}

namespace
{
    using SetLuaFunctions_t = void(__fastcall*)(lua_State* L);
    using FoxLuaRegisterLibrary_t = void(__fastcall*)(lua_State* L, const char* libName, luaL_Reg* funcs);
    using lua_tolstring_t = const char* (__fastcall*)(lua_State* L, int idx, size_t* len);
    using lua_tointeger_t = long long(__fastcall*)(lua_State* L, int idx);
    using lua_tonumber_t = lua_Number(__fastcall*)(lua_State* L, int idx);
    using lua_pushnumber_t = void(__fastcall*)(lua_State* L, lua_Number n);

    static SetLuaFunctions_t       g_OrigSetLuaFunctions = nullptr;
    static FoxLuaRegisterLibrary_t g_FoxLuaRegisterLibrary = nullptr;
    static lua_tolstring_t         g_lua_tolstring = nullptr;
    static lua_tointeger_t         g_lua_tointeger = nullptr;
    static lua_tonumber_t   g_lua_tonumber = nullptr;
    static lua_pushnumber_t g_lua_pushnumber = nullptr;

    static std::unordered_set<lua_State*> g_RegisteredLuaStates;
}

// Resolves the Lua/game functions used by this bridge file.
static bool ResolveLuaApi()
{
    if (!g_FoxLuaRegisterLibrary)
    {
        g_FoxLuaRegisterLibrary = reinterpret_cast<FoxLuaRegisterLibrary_t>(
            ResolveGameAddress(gAddr.FoxLuaRegisterLibrary));
    }

    if (!g_lua_tolstring)
    {
        g_lua_tolstring = reinterpret_cast<lua_tolstring_t>(
            ResolveGameAddress(gAddr.lua_tolstring));
    }

    if (!g_lua_tointeger)
    {
        g_lua_tointeger = reinterpret_cast<lua_tointeger_t>(
            ResolveGameAddress(gAddr.lua_tointeger));
    }

    if (!g_lua_tonumber)
    {
        g_lua_tonumber = reinterpret_cast<lua_tonumber_t>(
            ResolveGameAddress(gAddr.lua_tonumber));
    }

    if (!g_lua_pushnumber)
    {
        g_lua_pushnumber = reinterpret_cast<lua_pushnumber_t>(
            ResolveGameAddress(gAddr.lua_pushnumber));
    }

    return g_FoxLuaRegisterLibrary &&
        g_lua_tolstring &&
        g_lua_tointeger &&
        g_lua_tonumber &&
        g_lua_pushnumber;
}

// Registers the V_Restored_Languages Lua library in the given Lua state.
static bool RegisterLuaLibrary(lua_State* L, const char* libName, luaL_Reg* funcs)
{
    if (!ResolveLuaApi() || !L || !libName || !funcs)
        return false;

    g_FoxLuaRegisterLibrary(L, libName, funcs);
    Log("[V_Restored_Languages] Registered library: %s (L=%p)\n", libName, L);
    return true;
}

// Returns a Lua string argument or nullptr if unavailable.
// Params: L (lua_State*), idx (int)
static const char* GetLuaString(lua_State* L, int idx)
{
    if (!ResolveLuaApi() || !g_lua_tolstring)
        return nullptr;

    return g_lua_tolstring(L, idx, nullptr);
}

// Returns a Lua integer argument using the game's Lua thunk.
// Params: L (lua_State*), idx (int)
static int GetLuaInt(lua_State* L, int idx)
{
    if (!ResolveLuaApi() || !g_lua_tointeger)
        return 0;

    return static_cast<int>(g_lua_tointeger(L, idx));
}
// Returns a Lua number argument using the game's Lua thunk.
static float GetLuaNumber(lua_State* L, int idx)
{
    if (!ResolveLuaApi() || !g_lua_tonumber)
        return 0.0f;

    return static_cast<float>(g_lua_tonumber(L, idx));
}

// Pushes a Lua number using the game's Lua thunk.
static void PushLuaNumber(lua_State* L, float value)
{
    if (!ResolveLuaApi() || !g_lua_pushnumber)
        return;

    g_lua_pushnumber(L, static_cast<lua_Number>(value));
}

static luaL_Reg g_V_Restored_Languages[] =
{   //SetDefaultEquipBgTexturePath is the one that is going to be used in lua.
    //{ "SetDefaultEquipBgTexturePath",               l_SetDefaultEquipBgTexturePath },

    { nullptr, nullptr }
};

// Registers V_Restored_Languages into a UI Lua state only once.
static void RegisterAllUiLuaLibraries(lua_State* L)
{
    if (!L)
        return;

    if (g_RegisteredLuaStates.find(L) != g_RegisteredLuaStates.end())
        return;

    RegisterLuaLibrary(L, "V_Restored_Languages", g_V_Restored_Languages);
    g_RegisteredLuaStates.insert(L);
}// Registers V_Restored_Languages into a UI Lua state only once.


// Hooked version of SetLuaFunctions that appends V_Restored_Languages registration.
static void __fastcall hkSetLuaFunctions(lua_State* L)
{
    g_OrigSetLuaFunctions(L);
    RegisterAllUiLuaLibraries(L);
}

// Exported Lua loader for require("V_Restored_Languages").
extern "C" __declspec(dllexport) int __cdecl luaopen_V_Restored_Languages(lua_State* L)
{
    return RegisterLuaLibrary(L, "V_Restored_Languages", g_V_Restored_Languages) ? 1 : 0;
}

// Installs the SetLuaFunctions hook.
bool Install_SetLuaFunctions_Hook()
{
    ResolveLuaApi();

    void* target = ResolveGameAddress(gAddr.SetLuaFunctions);
    if (!target)
        return false;

    const bool ok = CreateAndEnableHook(
        target,
        reinterpret_cast<void*>(&hkSetLuaFunctions),
        reinterpret_cast<void**>(&g_OrigSetLuaFunctions));

    Log("[Hook] SetLuaFunctions: %s\n", ok ? "OK" : "FAIL");
    return ok;
}

// Removes the SetLuaFunctions hook.
bool Uninstall_SetLuaFunctions_Hook()
{
    DisableAndRemoveHook(ResolveGameAddress(gAddr.SetLuaFunctions));
    g_OrigSetLuaFunctions = nullptr;
    g_RegisteredLuaStates.clear();
    return true;
}