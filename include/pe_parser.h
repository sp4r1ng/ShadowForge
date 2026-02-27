#pragma once
#include "shadowforge.h"

class PEParser {
public:
    PEParser() = default;
    ~PEParser() = default;

    bool LoadFile(const std::string& filePath);

    void PrintDosHeader()  const;
    void PrintNTHeaders()  const;
    void PrintSections()   const;
    void PrintImports()    const;
    void PrintExports()    const;
    void PrintAll()        const;

    bool            IsLoaded()  const { return m_loaded; }
    bool            Is64Bit()   const { return m_is64; }
    const uint8_t*  RawData()   const { return m_rawData.data(); }
    size_t          RawSize()   const { return m_rawData.size(); }

private:
    bool                    m_loaded = false;
    bool                    m_is64   = false;
    std::vector<uint8_t>    m_rawData;
    std::string             m_filePath;

    PIMAGE_DOS_HEADER       m_dosHeader   = nullptr;
    PIMAGE_NT_HEADERS64     m_ntHeaders64 = nullptr;
    PIMAGE_NT_HEADERS32     m_ntHeaders32 = nullptr;
    PIMAGE_SECTION_HEADER   m_sections    = nullptr;
    WORD                    m_numSections = 0;

    DWORD       RvaToOffset(DWORD rva) const;
    const char* MachineToString(WORD machine) const;
    const char* SubsystemToString(WORD subsystem) const;
    std::string SectionFlagsToString(DWORD flags) const;
};
