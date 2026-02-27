#include "unhooker.h"

HMODULE NtdllUnhooker::GetLoadedNtdll() {
    return GetModuleHandleA("ntdll.dll");
}

bool NtdllUnhooker::ReadCleanNtdll(std::vector<uint8_t>& out) {
    char sysDir[MAX_PATH] = {};
    GetSystemDirectoryA(sysDir, MAX_PATH);
    std::string path = std::string(sysDir) + "\\ntdll.dll";

    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { PrintErr("Cannot read ntdll from disk."); return false; }

    DWORD size = GetFileSize(hFile, nullptr);
    out.resize(size);
    DWORD read = 0;
    ReadFile(hFile, out.data(), size, &read, nullptr);
    CloseHandle(hFile);

    if (read != size) { PrintErr("Incomplete read."); return false; }

    char buf[128];
    snprintf(buf, sizeof(buf), "Read clean ntdll: %lu bytes", (unsigned long)size);
    PrintOk(buf);
    return true;
}

bool NtdllUnhooker::FindTextSection(const uint8_t* pe, DWORD& rva, DWORD& size, DWORD& rawOff) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe);
    auto nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(pe + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {};
        memcpy(name, sec[i].Name, 8);
        if (strcmp(name, ".text") == 0) {
            rva    = sec[i].VirtualAddress;
            size   = sec[i].Misc.VirtualSize;
            rawOff = sec[i].PointerToRawData;
            return true;
        }
    }
    return false;
}

bool NtdllUnhooker::Unhook() {
    PrintInfo("Starting NTDLL unhooking...");

    HMODULE hNtdll = GetLoadedNtdll();
    if (!hNtdll) { PrintErr("ntdll not found."); return false; }

    char buf[256];
    snprintf(buf, sizeof(buf), "In-memory base: 0x%p", (void*)hNtdll);
    PrintInfo(buf);

    std::vector<uint8_t> clean;
    if (!ReadCleanNtdll(clean)) return false;

    DWORD textRva = 0, textSize = 0, textRaw = 0;
    if (!FindTextSection(clean.data(), textRva, textSize, textRaw)) {
        PrintErr(".text section not found."); return false;
    }

    snprintf(buf, sizeof(buf), ".text: RVA=0x%08lX  Size=0x%08lX",
             (unsigned long)textRva, (unsigned long)textSize);
    PrintInfo(buf);
    m_textSize = textSize;

    uint8_t* hooked      = reinterpret_cast<uint8_t*>(hNtdll) + textRva;
    const uint8_t* fresh = clean.data() + textRaw;

    m_bytesPatched = 0;
    for (DWORD i = 0; i < textSize; i++)
        if (hooked[i] != fresh[i]) m_bytesPatched++;

    if (m_bytesPatched == 0) { PrintOk("No hooks detected."); return true; }

    snprintf(buf, sizeof(buf), "Found %zu modified bytes", m_bytesPatched);
    PrintWarn(buf);

    DWORD oldProt = 0;
    if (!VirtualProtect(hooked, textSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
        PrintErr("VirtualProtect failed."); return false;
    }

    memcpy(hooked, fresh, textSize);
    VirtualProtect(hooked, textSize, oldProt, &oldProt);

    // Verify
    m_bytesPatched = 0;
    for (DWORD i = 0; i < textSize; i++)
        if (hooked[i] != fresh[i]) m_bytesPatched++;

    if (m_bytesPatched == 0) PrintOk("Unhooking verified — .text restored.");
    else PrintWarn("Some bytes still differ.");

    return true;
}
