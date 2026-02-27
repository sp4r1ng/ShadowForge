#pragma once
#include "shadowforge.h"

class EtwPatcher {
public:
    EtwPatcher() = default;

    bool PatchEtwEventWrite();
    bool PatchEtwEventWriteFull();
    bool PatchAll();
    bool IsPatched(const char* moduleName, const char* funcName) const;

private:
    bool    PatchFunction(const char* moduleName, const char* funcName);
    uint8_t m_originalBytes[8] = {};
};
