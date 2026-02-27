#include "pe_parser.h"

bool PEParser::LoadFile(const std::string& filePath) {
    m_filePath = filePath;
    m_loaded = false;

    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintErr(("Failed to open: " + filePath).c_str());
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        PrintErr("File too small for a valid PE.");
        CloseHandle(hFile);
        return false;
    }

    m_rawData.resize(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, m_rawData.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    if (bytesRead != fileSize) { PrintErr("Incomplete read."); return false; }

    m_dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_rawData.data());
    if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { PrintErr("Invalid DOS signature."); return false; }

    auto ntBase = m_rawData.data() + m_dosHeader->e_lfanew;
    if (*reinterpret_cast<DWORD*>(ntBase) != IMAGE_NT_SIGNATURE) { PrintErr("Invalid NT signature."); return false; }

    auto fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(ntBase + 4);
    m_is64 = (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64);

    if (m_is64) {
        m_ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntBase);
        m_sections    = IMAGE_FIRST_SECTION(m_ntHeaders64);
        m_numSections = m_ntHeaders64->FileHeader.NumberOfSections;
    } else {
        m_ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(ntBase);
        m_sections    = IMAGE_FIRST_SECTION(m_ntHeaders32);
        m_numSections = m_ntHeaders32->FileHeader.NumberOfSections;
    }

    m_loaded = true;
    PrintOk(("Loaded: " + filePath + (m_is64 ? " (x64)" : " (x86)")).c_str());
    return true;
}

DWORD PEParser::RvaToOffset(DWORD rva) const {
    for (WORD i = 0; i < m_numSections; i++) {
        DWORD start = m_sections[i].VirtualAddress;
        if (rva >= start && rva < start + m_sections[i].Misc.VirtualSize)
            return m_sections[i].PointerToRawData + (rva - start);
    }
    return 0;
}

const char* PEParser::MachineToString(WORD m) const {
    switch (m) {
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_ARM:   return "ARM";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default: return "Unknown";
    }
}

const char* PEParser::SubsystemToString(WORD s) const {
    switch (s) {
        case IMAGE_SUBSYSTEM_NATIVE:      return "Native";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "Windows Console";
        default: return "Unknown";
    }
}

std::string PEParser::SectionFlagsToString(DWORD f) const {
    std::string r;
    if (f & IMAGE_SCN_MEM_READ)    r += "R";
    if (f & IMAGE_SCN_MEM_WRITE)   r += "W";
    if (f & IMAGE_SCN_MEM_EXECUTE) r += "X";
    if (f & IMAGE_SCN_CNT_CODE)    r += " CODE";
    if (f & IMAGE_SCN_CNT_INITIALIZED_DATA)   r += " IDATA";
    if (f & IMAGE_SCN_CNT_UNINITIALIZED_DATA) r += " UDATA";
    return r;
}

void PEParser::PrintDosHeader() const {
    if (!m_loaded) return;
    Color::Cyan();
    std::cout << "\n  === DOS HEADER ===\n";
    Color::Reset();
    printf("    e_magic  : 0x%04X\n", m_dosHeader->e_magic);
    printf("    e_lfanew : 0x%08lX\n", (unsigned long)m_dosHeader->e_lfanew);
}

void PEParser::PrintNTHeaders() const {
    if (!m_loaded) return;
    Color::Cyan();
    printf("\n  === NT HEADERS (%s) ===\n", m_is64 ? "PE32+" : "PE32");
    Color::Reset();

    const IMAGE_FILE_HEADER* fh = m_is64 ? &m_ntHeaders64->FileHeader : &m_ntHeaders32->FileHeader;
    printf("    Machine          : 0x%04X (%s)\n", fh->Machine, MachineToString(fh->Machine));
    printf("    Sections         : %d\n", fh->NumberOfSections);
    printf("    TimeDateStamp    : 0x%08lX\n", (unsigned long)fh->TimeDateStamp);
    printf("    Characteristics  : 0x%04X\n", fh->Characteristics);

    if (m_is64) {
        auto& oh = m_ntHeaders64->OptionalHeader;
        printf("    EntryPoint       : 0x%08lX\n", (unsigned long)oh.AddressOfEntryPoint);
        printf("    ImageBase        : 0x%016llX\n", (unsigned long long)oh.ImageBase);
        printf("    SizeOfImage      : 0x%08lX\n", (unsigned long)oh.SizeOfImage);
        printf("    Subsystem        : %s\n", SubsystemToString(oh.Subsystem));
    } else {
        auto& oh = m_ntHeaders32->OptionalHeader;
        printf("    EntryPoint       : 0x%08lX\n", (unsigned long)oh.AddressOfEntryPoint);
        printf("    ImageBase        : 0x%08lX\n", (unsigned long)oh.ImageBase);
        printf("    SizeOfImage      : 0x%08lX\n", (unsigned long)oh.SizeOfImage);
        printf("    Subsystem        : %s\n", SubsystemToString(oh.Subsystem));
    }
}

void PEParser::PrintSections() const {
    if (!m_loaded) return;
    Color::Cyan();
    printf("\n  === SECTIONS (%d) ===\n", m_numSections);
    Color::Reset();
    printf("    %-10s %-12s %-12s %-12s %s\n", "Name", "VirtAddr", "VirtSize", "RawSize", "Flags");

    for (WORD i = 0; i < m_numSections; i++) {
        char name[9] = {};
        memcpy(name, m_sections[i].Name, 8);
        printf("    %-10s 0x%08lX   0x%08lX   0x%08lX   %s\n", name,
               (unsigned long)m_sections[i].VirtualAddress,
               (unsigned long)m_sections[i].Misc.VirtualSize,
               (unsigned long)m_sections[i].SizeOfRawData,
               SectionFlagsToString(m_sections[i].Characteristics).c_str());
    }
}

void PEParser::PrintImports() const {
    if (!m_loaded) return;
    Color::Cyan();
    std::cout << "\n  === IMPORTS ===\n";
    Color::Reset();

    DWORD importRva = 0, importSize = 0;
    if (m_is64) {
        if (m_ntHeaders64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return;
        importRva  = m_ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = m_ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        if (m_ntHeaders32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return;
        importRva  = m_ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = m_ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    if (!importRva) { PrintWarn("No imports."); return; }

    DWORD importOff = RvaToOffset(importRva);
    if (!importOff || importOff + importSize > m_rawData.size()) return;

    auto desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        const_cast<uint8_t*>(m_rawData.data()) + importOff);

    int count = 0;
    while (desc->Name) {
        DWORD nameOff = RvaToOffset(desc->Name);
        if (!nameOff || nameOff >= m_rawData.size()) break;

        Color::Yellow();
        printf("\n    [%s]\n", reinterpret_cast<const char*>(m_rawData.data() + nameOff));
        Color::Reset();

        DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        DWORD thunkOff = RvaToOffset(thunkRva);

        if (thunkOff && thunkOff < m_rawData.size()) {
            int fc = 0;
            if (m_is64) {
                auto t = reinterpret_cast<PIMAGE_THUNK_DATA64>(const_cast<uint8_t*>(m_rawData.data()) + thunkOff);
                while (t->u1.AddressOfData && fc++ < 50) {
                    if (!(t->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                        DWORD ho = RvaToOffset((DWORD)(t->u1.AddressOfData & 0xFFFFFFFF));
                        if (ho && ho + 2 < m_rawData.size()) {
                            auto h = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(const_cast<uint8_t*>(m_rawData.data()) + ho);
                            printf("      %s\n", h->Name);
                        }
                    }
                    t++;
                }
            } else {
                auto t = reinterpret_cast<PIMAGE_THUNK_DATA32>(const_cast<uint8_t*>(m_rawData.data()) + thunkOff);
                while (t->u1.AddressOfData && fc++ < 50) {
                    if (!(t->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                        DWORD ho = RvaToOffset(t->u1.AddressOfData);
                        if (ho && ho + 2 < m_rawData.size()) {
                            auto h = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(const_cast<uint8_t*>(m_rawData.data()) + ho);
                            printf("      %s\n", h->Name);
                        }
                    }
                    t++;
                }
            }
        }
        desc++;
        count++;
    }
    printf("\n    %d DLL(s) imported\n", count);
}

void PEParser::PrintExports() const {
    if (!m_loaded) return;
    Color::Cyan();
    std::cout << "\n  === EXPORTS ===\n";
    Color::Reset();

    DWORD exportRva = 0;
    if (m_is64) {
        if (m_ntHeaders64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return;
        exportRva = m_ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } else {
        if (m_ntHeaders32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return;
        exportRva = m_ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }
    if (!exportRva) { PrintWarn("No exports."); return; }

    DWORD exportOff = RvaToOffset(exportRva);
    if (!exportOff || exportOff + sizeof(IMAGE_EXPORT_DIRECTORY) > m_rawData.size()) return;

    auto dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(const_cast<uint8_t*>(m_rawData.data()) + exportOff);

    DWORD nameOff = RvaToOffset(dir->Name);
    printf("    DLL: %s  |  Functions: %lu  |  Names: %lu\n",
           (nameOff && nameOff < m_rawData.size()) ? reinterpret_cast<const char*>(m_rawData.data() + nameOff) : "?",
           (unsigned long)dir->NumberOfFunctions, (unsigned long)dir->NumberOfNames);

    DWORD nOff = RvaToOffset(dir->AddressOfNames);
    DWORD fOff = RvaToOffset(dir->AddressOfFunctions);
    DWORD oOff = RvaToOffset(dir->AddressOfNameOrdinals);
    if (!nOff || !fOff || !oOff) return;

    auto names = reinterpret_cast<const DWORD*>(m_rawData.data() + nOff);
    auto funcs = reinterpret_cast<const DWORD*>(m_rawData.data() + fOff);
    auto ords  = reinterpret_cast<const WORD*>(m_rawData.data() + oOff);

    int shown = 0;
    for (DWORD i = 0; i < dir->NumberOfNames && shown < 100; i++) {
        DWORD fnOff = RvaToOffset(names[i]);
        if (!fnOff || fnOff >= m_rawData.size()) continue;
        printf("    [%4d] 0x%08lX  %s\n", ords[i] + dir->Base,
               (unsigned long)funcs[ords[i]],
               reinterpret_cast<const char*>(m_rawData.data() + fnOff));
        shown++;
    }
    if (shown >= 100) printf("    ... truncated\n");
}

void PEParser::PrintAll() const {
    PrintDosHeader();
    PrintNTHeaders();
    PrintSections();
    PrintImports();
    PrintExports();
}
