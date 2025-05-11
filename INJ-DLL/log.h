#pragma once

#define _LOG_BEGIN namespace Log {

#define _LOG_END };

#define DbgPrint Log::printf

_LOG_BEGIN

NTSTATUS Init();
NTSTATUS Close();
void write(LPCVOID data, DWORD cb);
void printf(PCSTR format, ...);
NTSTATUS Flush();

_LOG_END

