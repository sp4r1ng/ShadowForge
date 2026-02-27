#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <functional>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

using NtSyscallFn = NTSTATUS(NTAPI*)(PVOID, ...);

typedef struct _SF_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} SF_CLIENT_ID, *PSF_CLIENT_ID;

typedef struct _SF_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} SF_OBJECT_ATTRIBUTES, *PSF_OBJECT_ATTRIBUTES;

inline void SfInitObjectAttributes(SF_OBJECT_ATTRIBUTES* oa) {
    memset(oa, 0, sizeof(SF_OBJECT_ATTRIBUTES));
    oa->Length = sizeof(SF_OBJECT_ATTRIBUTES);
}

namespace Color {
    inline void Red()     { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY); }
    inline void Green()   { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    inline void Yellow()  { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    inline void Cyan()    { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    inline void Magenta() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    inline void White()   { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    inline void Reset()   { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }
}

inline void PrintOk(const char* msg)   { Color::Green();  std::cout << "  [+] "; Color::Reset(); std::cout << msg << std::endl; }
inline void PrintInfo(const char* msg)  { Color::Cyan();   std::cout << "  [*] "; Color::Reset(); std::cout << msg << std::endl; }
inline void PrintWarn(const char* msg)  { Color::Yellow(); std::cout << "  [!] "; Color::Reset(); std::cout << msg << std::endl; }
inline void PrintErr(const char* msg)   { Color::Red();    std::cout << "  [-] "; Color::Reset(); std::cout << msg << std::endl; }

inline void PrintBanner() {
    Color::Magenta();
    std::cout << R"(
   _____ __              __              ______
  / ___// /_  ____ _____/ /___ _      __/ ____/___  _________ ____
  \__ \/ __ \/ __ `/ __  / __ \ | /| / / /_  / __ \/ ___/ __ `/ _ \
 ___/ / / / / /_/ / /_/ / /_/ / |/ |/ / __/ / /_/ / /  / /_/ /  __/
/____/_/ /_/\__,_/\__,_/\____/|__/|__/_/    \____/_/   \__, /\___/
                                                       /____/
    )" << std::endl;
    Color::Yellow();
    std::cout << "        EDR Evasion Research Framework v1.0\n";
    Color::Reset();
    std::cout << "        [ Educational / Lab Use Only ]\n\n";
}
