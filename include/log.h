#pragma once
#include <cstdio>
#include <cstdarg>

void InitLog(int attempts = 30, bool useFallback = true);
void Log(const char* fmt, ...);
void LogDetail(const char* fmt, ...);
void FlushLog();
void CloseLog();
bool RL_DiagnosticsEnabled();
