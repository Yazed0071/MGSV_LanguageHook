#include "pch.h"

#include "log.h"
#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>

static FILE* g_LogFile = nullptr;
static ULONGLONG g_LastFlushTick = 0;
static constexpr ULONGLONG kFlushIntervalMs = 250;

void InitLog()
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
    strcat_s(path, "MGSV_ArabicHook.log");

    fopen_s(&g_LogFile, path, "w");
    if (g_LogFile)
    {
        setvbuf(g_LogFile, nullptr, _IOFBF, 64 * 1024);
        g_LastFlushTick = GetTickCount64();
        fprintf(g_LogFile, "[LOG] Log file created successfully.\n");
        fflush(g_LogFile);
    }
}

void Log(const char* fmt, ...)
{
    #if _DEBUG
    {
        va_list argsConsole;
        va_start(argsConsole, fmt);
        vprintf(fmt, argsConsole);
        va_end(argsConsole);
    }
    #endif // _DEBUG

    if (!g_LogFile)
        return;

    va_list args;
    va_start(args, fmt);
    vfprintf(g_LogFile, fmt, args);
    va_end(args);

    const ULONGLONG now = GetTickCount64();
    if (now - g_LastFlushTick >= kFlushIntervalMs)
    {
        g_LastFlushTick = now;
        fflush(g_LogFile);
    }
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
