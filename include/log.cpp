#include "pch.h"

#include "log.h"
#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <share.h>

static FILE* g_LogFile = nullptr;
static ULONGLONG g_LastFlushTick = 0;
static constexpr ULONGLONG kFlushIntervalMs = 250;

static unsigned g_LineCount = 0;
static constexpr unsigned kAlwaysFlushLines = 4000;

static std::atomic<long long> g_BytesWritten{ 0 };
static std::atomic<bool> g_LimitReached{ false };
static constexpr long long kQuietSizeLimit = 16ll * 1024 * 1024;

void InitLog(int attempts, bool useFallback)
{
    if (g_LogFile)
        return;

    #if _DEBUG
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);

    SetConsoleTitleA("MGSV Arabic Hook Console");
    #endif // _DEBUG

    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    char* lastSlash = strrchr(path, '\\');
    if (lastSlash) *(lastSlash + 1) = '\0';
    char fallback[MAX_PATH];
    char previous[MAX_PATH];
    strcpy_s(fallback, path);
    strcpy_s(previous, path);
    strcat_s(path, "MGSV_ArabicHook.log");
    strcat_s(fallback, "MGSV_ArabicHook.2.log");
    strcat_s(previous, "MGSV_ArabicHook.prev.log");

    for (int attempt = 0; attempt < attempts && !g_LogFile; ++attempt)
    {
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES)
            MoveFileExA(path, previous, MOVEFILE_REPLACE_EXISTING);
        g_LogFile = _fsopen(path, "w", _SH_DENYWR);
        if (!g_LogFile)
            Sleep(100);
    }
    if (!g_LogFile && useFallback)
        g_LogFile = _fsopen(fallback, "w", _SH_DENYWR);
    if (g_LogFile)
    {
        setvbuf(g_LogFile, nullptr, _IOFBF, 64 * 1024);
        g_LastFlushTick = GetTickCount64();
        fprintf(g_LogFile, "[LOG] Log file created successfully.\n");
        fflush(g_LogFile);
    }
}

static void WriteLine(const char* fmt, va_list args)
{
    #if _DEBUG
    {
        va_list argsConsole;
        va_copy(argsConsole, args);
        vprintf(fmt, argsConsole);
        va_end(argsConsole);
    }
    #endif // _DEBUG

    if (!g_LogFile || g_LimitReached.load(std::memory_order_relaxed))
        return;

    const int written = vfprintf(g_LogFile, fmt, args);
    if (written > 0 && g_BytesWritten.fetch_add(written, std::memory_order_relaxed) + written > kQuietSizeLimit &&
        !RL_DiagnosticsEnabled() && !g_LimitReached.exchange(true))
    {
        fprintf(g_LogFile,
                "[LOG] %lld MB written - the rest of this session is not logged.\n",
                kQuietSizeLimit / (1024 * 1024));
        fflush(g_LogFile);
        return;
    }

    if (g_LineCount < kAlwaysFlushLines)
    {
        ++g_LineCount;
        g_LastFlushTick = GetTickCount64();
        fflush(g_LogFile);
        return;
    }

    const ULONGLONG now = GetTickCount64();
    if (now - g_LastFlushTick >= kFlushIntervalMs)
    {
        g_LastFlushTick = now;
        fflush(g_LogFile);
    }
}

void Log(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    WriteLine(fmt, args);
    va_end(args);
}

void LogDetail(const char* fmt, ...)
{
    if (!RL_DiagnosticsEnabled())
        return;
    va_list args;
    va_start(args, fmt);
    WriteLine(fmt, args);
    va_end(args);
}

void FlushLog()
{
    if (g_LogFile)
        fflush(g_LogFile);
}

void CloseLog()
{
    if (g_LogFile)
    {
        fprintf(g_LogFile, "[LOG] Closing log.\n");
        fclose(g_LogFile);
        g_LogFile = nullptr;
    }

    #if _DEBUG
    FreeConsole();
    #endif // _DEBUG
}
