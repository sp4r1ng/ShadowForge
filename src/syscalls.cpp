#include "syscalls.h"

bool SyscallManager::ResolveSyscalls() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { PrintErr("Failed to get ntdll handle."); return false; }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)hNtdll + dos->e_lfanew);
    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress) { PrintErr("No export directory."); return false; }

    auto exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((BYTE*)hNtdll + expDir.VirtualAddress);
    auto nameRVAs = reinterpret_cast<DWORD*>((BYTE*)hNtdll + exp->AddressOfNames);
    auto funcRVAs = reinterpret_cast<DWORD*>((BYTE*)hNtdll + exp->AddressOfFunctions);
    auto ordinals = reinterpret_cast<WORD*>((BYTE*)hNtdll + exp->AddressOfNameOrdinals);

    // Collect Zw* stubs and sort by RVA to derive SSN ordering
    std::vector<SyscallEntry> entries;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = reinterpret_cast<const char*>((BYTE*)hNtdll + nameRVAs[i]);
        if (name[0] == 'Z' && name[1] == 'w')
            entries.push_back({name, 0, funcRVAs[ordinals[i]]});
    }
    if (entries.empty()) { PrintErr("No Zw* exports found."); return false; }

    std::sort(entries.begin(), entries.end(),
              [](const SyscallEntry& a, const SyscallEntry& b) { return a.rva < b.rva; });

    m_syscallMap.clear();
    for (DWORD i = 0; i < entries.size(); i++) {
        m_syscallMap[entries[i].name] = i;
        m_syscallMap["Nt" + entries[i].name.substr(2)] = i;
    }

    m_resolved = true;
    char buf[64];
    snprintf(buf, sizeof(buf), "Resolved %zu syscalls", entries.size());
    PrintOk(buf);
    return true;
}

bool SyscallManager::GetSSN(const std::string& funcName, DWORD& outSSN) const {
    auto it = m_syscallMap.find(funcName);
    if (it == m_syscallMap.end()) return false;
    outSSN = it->second;
    return true;
}

void SyscallManager::PrintSyscallTable() const {
    if (!m_resolved) { PrintErr("Not resolved yet."); return; }

    Color::Cyan();
    std::cout << "\n  === SYSCALL TABLE ===\n";
    Color::Reset();

    std::vector<std::pair<std::string, DWORD>> ntEntries;
    for (auto& [name, ssn] : m_syscallMap)
        if (name.substr(0, 2) == "Nt") ntEntries.push_back({name, ssn});

    std::sort(ntEntries.begin(), ntEntries.end(),
              [](auto& a, auto& b) { return a.second < b.second; });

    const char* keys[] = {
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
        "NtOpenProcess", "NtOpenThread", "NtQueueApcThread",
        "NtCreateThreadEx", "NtCreateSection", "NtMapViewOfSection",
        "NtClose", "NtResumeThread", "NtReadVirtualMemory", nullptr
    };

    Color::Yellow(); std::cout << "\n    Key Syscalls:\n"; Color::Reset();
    for (int i = 0; keys[i]; i++) {
        auto it = m_syscallMap.find(keys[i]);
        if (it != m_syscallMap.end()) {
            Color::Green();
            printf("    0x%04lX", (unsigned long)it->second);
            Color::Reset();
            printf("  %s\n", it->first.c_str());
        }
    }

    Color::Yellow(); printf("\n    Full Table (%zu entries):\n", ntEntries.size()); Color::Reset();
    for (auto& [name, ssn] : ntEntries)
        printf("    0x%04lX  %s\n", (unsigned long)ssn, name.c_str());
}

// Wrappers
NTSTATUS SyscallManager::SysNtAllocateVirtualMemory(HANDLE p, PVOID* b, ULONG_PTR z, PSIZE_T s, ULONG a, ULONG pr) {
    DWORD ssn; if (!GetSSN("NtAllocateVirtualMemory", ssn)) return STATUS_NOT_FOUND;
    return DoSyscall(ssn, p, b, z, s, a, pr);
}
NTSTATUS SyscallManager::SysNtWriteVirtualMemory(HANDLE p, PVOID b, PVOID buf, SIZE_T n, PSIZE_T w) {
    DWORD ssn; if (!GetSSN("NtWriteVirtualMemory", ssn)) return STATUS_NOT_FOUND;
    return DoSyscall(ssn, p, b, buf, n, w);
}
NTSTATUS SyscallManager::SysNtProtectVirtualMemory(HANDLE p, PVOID* b, PSIZE_T s, ULONG np, PULONG op) {
    DWORD ssn; if (!GetSSN("NtProtectVirtualMemory", ssn)) return STATUS_NOT_FOUND;
    return DoSyscall(ssn, p, b, s, np, op);
}
NTSTATUS SyscallManager::SysNtOpenProcess(PHANDLE p, ACCESS_MASK d, PSF_OBJECT_ATTRIBUTES o, PSF_CLIENT_ID c) {
    DWORD ssn; if (!GetSSN("NtOpenProcess", ssn)) return STATUS_NOT_FOUND;
    return DoSyscall(ssn, p, d, o, c);
}
NTSTATUS SyscallManager::SysNtQueueApcThread(HANDLE t, PVOID r, PVOID a1, PVOID a2, PVOID a3) {
    DWORD ssn; if (!GetSSN("NtQueueApcThread", ssn)) return STATUS_NOT_FOUND;
    return DoSyscall(ssn, t, r, a1, a2, a3);
}
NTSTATUS SyscallManager::SysNtClose(HANDLE h) {
    DWORD ssn; if (!GetSSN("NtClose", ssn)) return STATUS_NOT_FOUND;
    return DoSyscall(ssn, h);
}
NTSTATUS SyscallManager::SysNtResumeThread(HANDLE t, PULONG p) {
    DWORD ssn; if (!GetSSN("NtResumeThread", ssn)) return STATUS_NOT_FOUND;
    return DoSyscall(ssn, t, p);
}
