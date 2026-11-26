#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>

#include "AddressSet.h"
#include "HookUtils.h"
#include "log.h"

namespace
{
    constexpr uintptr_t kStateTt = 0x08;
    constexpr uintptr_t kStateTop = 0x10;
    constexpr uintptr_t kStateBase = 0x18;
    constexpr uintptr_t kStateGlobal = 0x20;
    constexpr uintptr_t kStateCi = 0x28;
    constexpr uintptr_t kStateSavedPc = 0x30;
    constexpr uintptr_t kStateStackLast = 0x38;
    constexpr uintptr_t kStateStack = 0x40;
    constexpr uintptr_t kStateEndCi = 0x48;
    constexpr uintptr_t kStateBaseCi = 0x50;
    constexpr uintptr_t kCallInfoSize = 0x28;
    constexpr uintptr_t kCallInfoFunc = 0x08;
    constexpr uintptr_t kCallInfoSavedPc = 0x18;
    constexpr uintptr_t kClosureIsC = 0x0A;
    constexpr uintptr_t kClosureBody = 0x20;
    constexpr uintptr_t kProtoCode = 0x18;
    constexpr uintptr_t kProtoLineInfo = 0x28;
    constexpr uintptr_t kProtoSource = 0x40;
    constexpr uintptr_t kProtoSizeLineInfo = 0x54;
    constexpr uintptr_t kProtoLineDefined = 0x60;
    constexpr uintptr_t kStringLength = 0x10;
    constexpr uintptr_t kStringChars = 0x18;
    constexpr uint32_t kTypeString = 4;
    constexpr uint32_t kTypeFunction = 6;
    constexpr uint8_t kTypeThread = 8;
    constexpr int kMaxFrames = 40;
    constexpr int kStackWordsToScan = 160;

    PVOID gHandler = nullptr;
    uintptr_t gLuaBegin = 0;
    uintptr_t gLuaEnd = 0;
    std::atomic<bool> gReported{ false };

    bool ReadBytes(uintptr_t addr, void* out, size_t size)
    {
        if (addr < 0x10000)
            return false;

        __try
        {
            memcpy(out, reinterpret_cast<const void*>(addr), size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    template <typename T>
    bool ReadValue(uintptr_t addr, T& out)
    {
        return ReadBytes(addr, &out, sizeof(T));
    }

    bool IsLuaState(uintptr_t L)
    {
        if (L < 0x10000 || (L & 7))
            return false;

        uint8_t tt = 0;
        if (!ReadValue(L + kStateTt, tt) || tt != kTypeThread)
            return false;

        uintptr_t top = 0, base = 0, global = 0, ci = 0, stackLast = 0, stack = 0, endCi = 0, baseCi = 0;
        if (!ReadValue(L + kStateTop, top) || !ReadValue(L + kStateBase, base) ||
            !ReadValue(L + kStateGlobal, global) || !ReadValue(L + kStateCi, ci) ||
            !ReadValue(L + kStateStackLast, stackLast) || !ReadValue(L + kStateStack, stack) ||
            !ReadValue(L + kStateEndCi, endCi) || !ReadValue(L + kStateBaseCi, baseCi))
            return false;

        return global && stack && stack <= base && base <= top && top <= stackLast + 0x100 &&
            baseCi && baseCi <= ci && ci <= endCi && (ci - baseCi) % kCallInfoSize == 0;
    }

    bool ReadLuaString(uintptr_t ts, char* out, size_t cap)
    {
        uint8_t tt = 0;
        uint64_t len = 0;
        uintptr_t chars = 0;
        if (!ts || !ReadValue(ts + kStateTt, tt) || tt != kTypeString || !ReadValue(ts + kStringLength, len) ||
            len > 0x100000 || !ReadValue(ts + kStringChars, chars) || !chars)
            return false;

        const size_t n = static_cast<size_t>(len < cap - 1 ? len : cap - 1);
        if (!ReadBytes(chars + static_cast<uintptr_t>(len - n), out, n))
            return false;

        out[n] = 0;
        return true;
    }

    const char* ModuleOf(uintptr_t addr, uintptr_t& base, char* buffer, DWORD cap)
    {
        HMODULE module = nullptr;
        base = 0;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(addr), &module) || !module)
            return "?";

        base = reinterpret_cast<uintptr_t>(module);
        if (!GetModuleFileNameA(module, buffer, cap))
            return "?";

        const char* slash = strrchr(buffer, '\\');
        return slash ? slash + 1 : buffer;
    }

    bool LogFrame(int depth, uintptr_t func, uintptr_t pc)
    {
        uint64_t gc = 0;
        uint32_t type = 0;
        if (!ReadValue(func, gc) || !ReadValue(func + 8, type) || type != kTypeFunction)
            return false;

        uint8_t isC = 0;
        uintptr_t body = 0;
        if (!ReadValue(gc + kClosureIsC, isC) || !ReadValue(gc + kClosureBody, body))
            return false;

        if (isC)
        {
            char path[MAX_PATH] = {};
            uintptr_t base = 0;
            const char* name = ModuleOf(body, base, path, MAX_PATH);
            Log("[LuaCrash]   #%d C function %s+0x%llX\n", depth, name,
                static_cast<unsigned long long>(base ? body - base : body));
            return true;
        }

        uintptr_t code = 0, lineInfo = 0, source = 0;
        uint32_t sizeLineInfo = 0, lineDefined = 0;
        ReadValue(body + kProtoCode, code);
        ReadValue(body + kProtoLineInfo, lineInfo);
        ReadValue(body + kProtoSource, source);
        ReadValue(body + kProtoSizeLineInfo, sizeLineInfo);
        ReadValue(body + kProtoLineDefined, lineDefined);

        char chunk[260] = "?";
        ReadLuaString(source, chunk, sizeof(chunk));

        long long line = -1;
        if (pc > code && code && lineInfo)
        {
            const uintptr_t index = (pc - code) / 4 - 1;
            uint32_t value = 0;
            if (index < sizeLineInfo && ReadValue(lineInfo + index * 4, value))
                line = value;
        }

        Log("[LuaCrash]   #%d %s:%lld (function from line %u)\n", depth, chunk, line, lineDefined);
        return true;
    }

    void LogRegisterHints(const CONTEXT* ctx, uintptr_t L)
    {
        uintptr_t stack = 0, stackLast = 0, base = 0;
        ReadValue(L + kStateStack, stack);
        ReadValue(L + kStateStackLast, stackLast);
        ReadValue(L + kStateBase, base);

        const struct
        {
            const char* name;
            DWORD64 value;
        } regs[] = {
            { "rcx", ctx->Rcx }, { "rdx", ctx->Rdx }, { "rbx", ctx->Rbx }, { "rbp", ctx->Rbp },
            { "rsi", ctx->Rsi }, { "rdi", ctx->Rdi }, { "r8", ctx->R8 }, { "r9", ctx->R9 },
            { "r12", ctx->R12 }, { "r13", ctx->R13 }, { "r14", ctx->R14 }, { "r15", ctx->R15 },
        };

        for (const auto& reg : regs)
        {
            const uintptr_t at = static_cast<uintptr_t>(reg.value);
            char text[120] = {};
            uint64_t payload = 0;
            uint32_t type = 0;
            if (stack && at >= stack && at <= stackLast + 0x100 && (at - stack) % 16 == 0 &&
                ReadValue(at, payload) && ReadValue(at + 8, type))
            {
                const long long slot = base ? static_cast<long long>(at - base) / 16 : -1;
                if (type == kTypeString && ReadLuaString(static_cast<uintptr_t>(payload), text, sizeof(text)))
                    Log("[LuaCrash]   %s -> R(%lld): string \"%s\"\n", reg.name, slot, text);
                else
                    Log("[LuaCrash]   %s -> R(%lld): type %u payload 0x%llX%s\n", reg.name, slot, type,
                        static_cast<unsigned long long>(payload), type > kTypeThread ? " (not a valid Lua type)" : "");
            }
            else if (ReadLuaString(at, text, sizeof(text)))
            {
                Log("[LuaCrash]   %s is the Lua string \"%s\"\n", reg.name, text);
            }
        }
    }

    uintptr_t FindLuaState(const CONTEXT* ctx)
    {
        const DWORD64 regs[] = {
            ctx->Rsi, ctx->Rdi, ctx->Rbx, ctx->Rbp, ctx->R12, ctx->R13, ctx->R14, ctx->R15,
            ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9, ctx->Rax, ctx->R10, ctx->R11
        };

        for (DWORD64 value : regs)
        {
            if (IsLuaState(static_cast<uintptr_t>(value)))
                return static_cast<uintptr_t>(value);
        }

        for (int i = 0; i < kStackWordsToScan; ++i)
        {
            uintptr_t value = 0;
            if (ReadValue(static_cast<uintptr_t>(ctx->Rsp) + i * 8, value) && IsLuaState(value))
                return value;
        }

        return 0;
    }

    void Report(const EXCEPTION_RECORD* rec, const CONTEXT* ctx)
    {
        const uintptr_t exeBase = GetExeBase();
        const ULONG_PTR kind = rec->NumberParameters > 0 ? rec->ExceptionInformation[0] : 0;
        const ULONG_PTR target = rec->NumberParameters > 1 ? rec->ExceptionInformation[1] : 0;
        const char* access = kind == 1 ? "write to" : kind == 8 ? "execute at" : "read from";

        Log("[LuaCrash] access violation in the game's Lua code at mgsvtpp.exe+0x%llX (%s 0x%llX), thread %lu\n",
            static_cast<unsigned long long>(ctx->Rip - exeBase), access,
            static_cast<unsigned long long>(target), GetCurrentThreadId());

        const uintptr_t L = FindLuaState(ctx);
        if (!L)
        {
            Log("[LuaCrash] no Lua state found near the crash, so no Lua call stack\n");
            FlushLog();
            return;
        }

        uintptr_t ci = 0, baseCi = 0, savedPc = 0;
        ReadValue(L + kStateCi, ci);
        ReadValue(L + kStateBaseCi, baseCi);
        ReadValue(L + kStateSavedPc, savedPc);

        Log("[LuaCrash] Lua state %p, %llu call levels, innermost first:\n", reinterpret_cast<void*>(L),
            static_cast<unsigned long long>((ci - baseCi) / kCallInfoSize + 1));

        int depth = 0;
        for (uintptr_t c = ci; depth < kMaxFrames; c -= kCallInfoSize)
        {
            uintptr_t func = 0, framePc = 0;
            if (!ReadValue(c + kCallInfoFunc, func))
                break;

            ReadValue(c + kCallInfoSavedPc, framePc);
            if (LogFrame(depth, func, c == ci ? savedPc : framePc))
                ++depth;

            if (c <= baseCi)
                break;
        }

        Log("[LuaCrash] values the registers point at:\n");
        LogRegisterHints(ctx, L);
        FlushLog();
    }

    LONG CALLBACK LuaCrashHandler(PEXCEPTION_POINTERS info)
    {
        if (!info || !info->ExceptionRecord || !info->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        if (info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
            return EXCEPTION_CONTINUE_SEARCH;

        const uintptr_t rip = static_cast<uintptr_t>(info->ContextRecord->Rip);
        if (rip < gLuaBegin || rip >= gLuaEnd)
            return EXCEPTION_CONTINUE_SEARCH;

        if (gReported.exchange(true))
            return EXCEPTION_CONTINUE_SEARCH;

        Report(info->ExceptionRecord, info->ContextRecord);
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

bool InstallLuaCrashReport()
{
    if (!gAddr.LuaCodeBegin || gAddr.LuaCodeEnd <= gAddr.LuaCodeBegin)
    {
        Log("[LuaCrash] the game's Lua code range is unknown for this build, crash report off\n");
        return false;
    }

    gLuaBegin = reinterpret_cast<uintptr_t>(ResolveGameAddress(gAddr.LuaCodeBegin));
    gLuaEnd = reinterpret_cast<uintptr_t>(ResolveGameAddress(gAddr.LuaCodeEnd));
    if (!gHandler)
        gHandler = AddVectoredExceptionHandler(1, LuaCrashHandler);

    Log("[LuaCrash] crash report armed for the game's Lua code 0x%llX-0x%llX\n",
        static_cast<unsigned long long>(gLuaBegin), static_cast<unsigned long long>(gLuaEnd));
    return gHandler != nullptr;
}

void RemoveLuaCrashReport()
{
    if (gHandler)
    {
        RemoveVectoredExceptionHandler(gHandler);
        gHandler = nullptr;
    }
}
