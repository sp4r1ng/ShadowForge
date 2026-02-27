#pragma once
#include "shadowforge.h"

class NtdllUnhooker {
public:
    NtdllUnhooker() = default;

    bool   Unhook();
    size_t GetBytesPatched()    const { return m_bytesPatched; }
    size_t GetTextSectionSize() const { return m_textSize; }

private:
    size_t m_bytesPatched = 0;
    size_t m_textSize     = 0;

    HMODULE GetLoadedNtdll();
    bool    ReadCleanNtdll(std::vector<uint8_t>& outData);
    bool    FindTextSection(const uint8_t* peData, DWORD& outRva, DWORD& outSize, DWORD& outRawOffset);
};
