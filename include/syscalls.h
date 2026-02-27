#pragma once
#include "shadowforge.h"

extern "C" NTSTATUS DoSyscall(DWORD ssn, ...);

struct SyscallEntry {
    std::string name;
    DWORD       ssn;
    DWORD       rva;
};

class SyscallManager {
public:
    SyscallManager() = default;

    bool ResolveSyscalls();
    bool GetSSN(const std::string& funcName, DWORD& outSSN) const;
    void PrintSyscallTable() const;

    NTSTATUS SysNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS SysNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS SysNtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    NTSTATUS SysNtOpenProcess(PHANDLE, ACCESS_MASK, PSF_OBJECT_ATTRIBUTES, PSF_CLIENT_ID);
    NTSTATUS SysNtQueueApcThread(HANDLE, PVOID, PVOID, PVOID, PVOID);
    NTSTATUS SysNtClose(HANDLE);
    NTSTATUS SysNtResumeThread(HANDLE, PULONG);

private:
    std::map<std::string, DWORD> m_syscallMap;
    bool m_resolved = false;
};
