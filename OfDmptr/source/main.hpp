#pragma once
#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <vector>
#include <thread>
#include <filesystem>
#include <regex>
#include <unordered_set>
#include <optional>
#include <functional>
#include "TlHelp32.h"
#include <chrono>
#include <psapi.h>
//#include <nlohmann/json.hpp>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <filesystem>
#include <vector>
#include <algorithm>
#include "Security/xorstr.hpp"


#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "dbghelp.lib")
struct GlobalState {
    HANDLE processHandle = nullptr;
    DWORD processId = 0;
    HWND windowHandle = nullptr;
    uintptr_t dataModelAddress = 0;
};

// Global state instance
namespace Globals {
    inline GlobalState state;
}

struct OffsetContainer {
    struct AddressContainer {
        uintptr_t DatamodelPtr = 0x0;
        uintptr_t DatamodelDeleter = 0x0;
        uintptr_t RawTaskScheduler = 0x0;
    };

    uintptr_t name = 0x0;
    uintptr_t workspace = 0x0;
    uintptr_t placeid = 0x0;
    uintptr_t parent = 0x0;
    uintptr_t classdescriptor = 0x0;
    uintptr_t children = 0x0;
    uintptr_t loaded = 0x0;
    uintptr_t camera = 0x0;
    uintptr_t fov = 0x0;
    uintptr_t walkspeedA = 0x0;
    uintptr_t walkspeedB = 0x0;
    uintptr_t localplayer = 0x0;
    uintptr_t JumpPower = 0x0;
    uintptr_t userid = 0x0;
    uintptr_t gravity = 0x0;
    uintptr_t gravitys = 0x0;
    uintptr_t health = 0x0;
    uintptr_t anchored = 0x0;
    uintptr_t childrenend = 0x0;
    uintptr_t cancollide = 0x0;



    uintptr_t rootpart = 0x0;
    uintptr_t character = 0x0;
    uintptr_t humanoid = 0x0;
    // pack hier als init value deine offsets du du dumpen willst rein.

    AddressContainer Addresses;
};

namespace Offsets {
    inline OffsetContainer offsets;
}



namespace fs = std::filesystem;
// 
inline auto cPlaceId() {
    try {
        std::string localAppData = std::getenv("LOCALAPPDATA");
        fs::path robloxLogsPath = fs::path(localAppData) / "Roblox" / "logs";

        if (!fs::exists(robloxLogsPath) || !fs::is_directory(robloxLogsPath))
            return std::string("Error: Roblox logs directory not found.");

        std::vector<fs::directory_entry> logFiles;
        for (const auto& entry : fs::directory_iterator(robloxLogsPath)) {
            if (entry.is_regular_file() && entry.path().extension() == ".log") {
                logFiles.push_back(entry);
            }
        }

        std::sort(logFiles.begin(), logFiles.end(), [](const auto& a, const auto& b) {
            auto timeA = fs::last_write_time(a);
            auto timeB = fs::last_write_time(b);
            if (timeA != timeB)
                return timeA > timeB;
            return fs::file_size(a) > fs::file_size(b);
            });

        std::regex placeIdsRegex(R"(placeIds=(\d+))", std::regex_constants::icase);
        std::regex placeIdRegex(R"(placeid:(\d+))", std::regex_constants::icase);

        size_t maxFilesToCheck = std::min<size_t>(logFiles.size(), 5); // explicit template parameter

        for (size_t i = 0; i < maxFilesToCheck; ++i) {
            std::ifstream file(logFiles[i].path());
            if (!file.is_open())
                continue;

            std::string line;
            std::string lastPlaceId;

            while (std::getline(file, line)) {
                std::smatch match;
                if (std::regex_search(line, match, placeIdsRegex) && match.size() > 1)
                    lastPlaceId = match[1].str();
                if (std::regex_search(line, match, placeIdRegex) && match.size() > 1)
                    lastPlaceId = match[1].str();
            }

            if (!lastPlaceId.empty())
                return lastPlaceId;
        }

        return std::string();
    }
    catch (const std::exception& ex) {
        return std::string("Error: ") + ex.what();
    }
}
inline auto cUserId() {
    try {
        std::string localAppData = std::getenv("LOCALAPPDATA");
        fs::path robloxLogsPath = fs::path(localAppData) / "Roblox" / "logs";

        if (!fs::exists(robloxLogsPath) || !fs::is_directory(robloxLogsPath))
            return std::string("Error: Roblox logs directory not found.");

        std::vector<fs::directory_entry> logFiles;
        for (const auto& entry : fs::directory_iterator(robloxLogsPath)) {
            if (entry.is_regular_file() && entry.path().extension() == ".log") {
                logFiles.push_back(entry);
            }
        }

        std::sort(logFiles.begin(), logFiles.end(), [](const auto& a, const auto& b) {
            auto timeA = fs::last_write_time(a);
            auto timeB = fs::last_write_time(b);
            if (timeA != timeB)
                return timeA > timeB;
            return fs::file_size(a) > fs::file_size(b);
            });

        std::regex placeIdsRegex(R"("userId":(\d+))", std::regex_constants::icase);
        std::regex placeIdRegex(R"(userid":(\d+))", std::regex_constants::icase);

        size_t maxFilesToCheck = std::min<size_t>(logFiles.size(), 5); // explicit template parameter

        for (size_t i = 0; i < maxFilesToCheck; ++i) {
            std::ifstream file(logFiles[i].path());
            if (!file.is_open())
                continue;

            std::string line;
            std::string lastPlaceId;

            while (std::getline(file, line)) {
                std::smatch match;
                if (std::regex_search(line, match, placeIdsRegex) && match.size() > 1)
                    lastPlaceId = match[1].str();
                if (std::regex_search(line, match, placeIdRegex) && match.size() > 1)
                    lastPlaceId = match[1].str();
            }

            if (!lastPlaceId.empty())
                return lastPlaceId;
        }

        return std::string();
    }
    catch (const std::exception& ex) {
        return std::string("Error: ") + ex.what();
    }
}







class MemoryUtils {
public:
    static BOOL WriteMemory(HANDLE process, LPVOID BaseAddress, LPCVOID Buffer, SIZE_T BytesToWrite, PULONG BytesWritten) {
        SIZE_T actualBytesWritten = 0;
        BOOL result = WriteProcessMemory(process, BaseAddress, Buffer, BytesToWrite, &actualBytesWritten);

        if (BytesWritten) {
            *BytesWritten = static_cast<ULONG>(actualBytesWritten);
        }

        return result;
    }

    static BOOL ReadMemory(HANDLE process, LPCVOID BaseAddress, PVOID Buffer, SIZE_T BytesToRead, PULONG BytesRead) {
        SIZE_T actualBytesRead = 0;
        BOOL result = ReadProcessMemory(process, BaseAddress, Buffer, BytesToRead, &actualBytesRead);

        if (BytesRead) {
            *BytesRead = static_cast<ULONG>(actualBytesRead);
        }

        return result;
    }
};
template <typename T>
T read(uintptr_t address) {
    T buffer{};
    ULONG bytesRead = 0;
    if (MemoryUtils::ReadMemory(Globals::state.processHandle, reinterpret_cast<LPCVOID>(address), &buffer, sizeof(T), &bytesRead) &&
        bytesRead == sizeof(T)) {
        return buffer;
    }
    return T{};
}

template <typename T>
bool write(uintptr_t address, const T& value) {
    ULONG bytesWritten = 0;
    return MemoryUtils::WriteMemory(Globals::state.processHandle, reinterpret_cast<LPVOID>(address), &value, sizeof(T), &bytesWritten) &&
        bytesWritten == sizeof(T);
}
inline std::string readstring(std::uintptr_t address) {
    std::string buffer;
    buffer.reserve(204);

    for (int i = 0; i < 200; i++) {
        char c = read<char>(address + i);
        if (c == 0) break;
        buffer.push_back(c);
    }

    return buffer;
}
template <typename T>
T readmodule(uintptr_t offset) {
    T buffer{};
    DWORD moduleSize = 0;

    if (!Globals::state.processHandle) return buffer;

    HMODULE moduleHandle = nullptr;
    MODULEINFO moduleInfo = {};

    if (EnumProcessModules(Globals::state.processHandle, &moduleHandle, sizeof(moduleHandle), &moduleSize)) {
        if (GetModuleInformation(Globals::state.processHandle, moduleHandle, &moduleInfo, sizeof(moduleInfo))) {
            uintptr_t baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
            uintptr_t targetAddress = baseAddress + offset;
            NtReadVirtualMemory(Globals::state.processHandle, reinterpret_cast<LPCVOID>(targetAddress), &buffer, sizeof(T), nullptr);
        }
    }

    return buffer;
}
inline uintptr_t ParseHex(const std::string& hexString) {
    return strtoull(hexString.c_str(), nullptr, 16);
}
class MemoryManager {
public:
    template<typename T>
    T read(uintptr_t address) {
        T value{};
        ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), nullptr);
        return value;
    }

    template<typename T>
    void write(uintptr_t address, const T& value) {
        WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(address), &value, sizeof(T), nullptr);
    }

    std::unique_ptr<uint8_t[]> read(uintptr_t address, size_t size) {
        auto buffer = std::make_unique<uint8_t[]>(size);
        if (!ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(address), buffer.get(), size, nullptr)) {
            return nullptr;
        }
        return buffer;
    }

    std::vector<MEMORY_BASIC_INFORMATION> regions() {
        std::vector<MEMORY_BASIC_INFORMATION> regionsList;
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t currentAddress = 0;

        while (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(currentAddress), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)) {
                regionsList.push_back(mbi);
            }
            currentAddress += mbi.RegionSize;
        }

        return regionsList;
    }

    HANDLE processHandle;
};
struct ModuleInfo {
    uintptr_t baseAddress;
    size_t moduleSize;

    bool contains(uintptr_t address) const {
        return (address >= baseAddress) && (address < baseAddress + moduleSize);
    }
};
class ProcessManager {
public:
    static std::unique_ptr<ProcessManager> open(const std::string& processName) {
        DWORD processId = 0;
        PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (snapshot != INVALID_HANDLE_VALUE && Process32First(snapshot, &entry)) {
            do {
                if (processName == entry.szExeFile) {
                    processId = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
            CloseHandle(snapshot);
        }

        if (!processId) return nullptr;

        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!processHandle) return nullptr;

        auto processManager = std::make_unique<ProcessManager>();
        processManager->memoryManager.processHandle = processHandle;
        processManager->processHandle = processHandle;
        processManager->processId = processId;
        return processManager;
    }

    ~ProcessManager() {
        if (processHandle) CloseHandle(processHandle);
    }

    std::vector<ModuleInfo> modules() {
        std::vector<ModuleInfo> modulesList;
        MODULEENTRY32 moduleEntry = { sizeof(MODULEENTRY32) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

        if (snapshot != INVALID_HANDLE_VALUE && Module32First(snapshot, &moduleEntry)) {
            do {
                modulesList.push_back({
                    reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr),
                    static_cast<size_t>(moduleEntry.modBaseSize)
                    });
            } while (Module32Next(snapshot, &moduleEntry));
            CloseHandle(snapshot);
        }

        return modulesList;
    }

    HANDLE processHandle;
    DWORD processId;
    MemoryManager memoryManager;
};

// RTTI structures
struct RTTICompleteObjectLocator {
    DWORD signature;
    DWORD offset;
    DWORD cdOffset;
    DWORD typeDescriptor;
    DWORD classDescriptor;
    DWORD baseOffset;
};

struct TypeDescriptor {
    void* vtable;
    uint64_t ptr;
    char name[255];
};

// Logs
class LogFileUtils {
public:
    static std::optional<std::string> getLatestLogFile(const std::string& folderPath) {
        std::optional<std::string> latestFilePath;
        std::filesystem::file_time_type latestTimestamp;

        try {
            for (const auto& entry : std::filesystem::directory_iterator(folderPath)) {
                if (entry.is_regular_file() && entry.path().extension() == ".log") {
                    auto fileTimestamp = std::filesystem::last_write_time(entry);

                    if (!latestFilePath || fileTimestamp > latestTimestamp) {
                        latestFilePath = entry.path().string();
                        latestTimestamp = fileTimestamp;
                    }
                }
            }
        }
        catch (const std::exception&) {
            return std::nullopt;
        }

        return latestFilePath;
    }

    static std::string readFile(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file) {
            return "";
        }

        std::ostringstream content;
        content << file.rdbuf();
        return content.str();
    }
};

// Thread ID locator
class ThreadIdentifier {
public:
    static uintptr_t locateTid(const std::string& content) {
        std::regex pattern(R"(::replaceDataModel: \(stage:\d+, window = 0x[a-zA-Z\d]+\) \[tid:(0x[a-zA-Z\d]+)\])");
        std::smatch matches;
        std::string::const_iterator searchStart(content.cbegin());

        uintptr_t threadId = 0;
        while (std::regex_search(searchStart, content.cend(), matches, pattern)) {
            threadId = std::stoull(matches[1], nullptr, 16);
            searchStart = matches.suffix().first;
        }

        return threadId;
    }
};

class SymbolUtils {
public:
    static std::string demangleSymbol(const std::string& mangledName) {
        std::string demangledBuffer(1024, '\0');
        std::string nameCopy = mangledName;

        if (nameCopy.starts_with(".?AV")) {
            nameCopy = "?" + nameCopy.substr(4);
        }

        DWORD length = UnDecorateSymbolName(nameCopy.c_str(), demangledBuffer.data(), demangledBuffer.capacity(), UNDNAME_COMPLETE);
        if (!length) {
            return nameCopy;
        }

        demangledBuffer.resize(length);

        if (demangledBuffer.starts_with(" ??")) {
            demangledBuffer = demangledBuffer.substr(4);
        }

        return demangledBuffer;
    }
};

class ModuleUtils {
public:
    static uintptr_t getModuleContaining(std::unique_ptr<ProcessManager>& process, uintptr_t address) {
        for (const auto& module : process->modules()) {
            if (module.contains(address)) {
                return module.baseAddress;
            }
        }
        return 0;
    }

    static bool isValidAddress(std::unique_ptr<ProcessManager>& process, uintptr_t address) {
        auto buffer = process->memoryManager.read(address, 0x1);
        return buffer != nullptr;
    }
};
class RTTIUtils {
public:
    static std::optional<std::string> getRTTIName(std::unique_ptr<ProcessManager>& process, uintptr_t objectAddress) {

        uintptr_t vtableAddress = process->memoryManager.read<uintptr_t>(objectAddress);
        if (!vtableAddress) {
            return std::nullopt;
        }
        if (!ModuleUtils::isValidAddress(process, vtableAddress - sizeof(uintptr_t))) {
            return std::nullopt;
        }
        uintptr_t colAddress = process->memoryManager.read<uintptr_t>(vtableAddress - sizeof(uintptr_t));
        if (!colAddress || !ModuleUtils::isValidAddress(process, colAddress)) {
            return std::nullopt;
        }
        RTTICompleteObjectLocator col = process->memoryManager.read<RTTICompleteObjectLocator>(colAddress);
        uintptr_t typeInfoAddress = col.typeDescriptor + ModuleUtils::getModuleContaining(process, colAddress);

        if (!ModuleUtils::isValidAddress(process, typeInfoAddress)) {
            return std::nullopt;
        }
        TypeDescriptor typeInfo = process->memoryManager.read<TypeDescriptor>(typeInfoAddress);
        return SymbolUtils::demangleSymbol(typeInfo.name);
    }
};
namespace memory {
    enum class protection_flags_t {
        readwrite = 0x04,
        execute = 0x10,
        execute_readwrite = 0x20,
    };

    enum class state_t {
        commit_t = 0x1000,
        reserve_t = 0x2000,
        free_t = 0x10000
    };

    struct region_t {
        uintptr_t BaseAddress;
        size_t RegionSize;
        protection_flags_t Protect;
        state_t State;
    };
}
class ObjectTraverser {
public:
    static void recursivePointerWalk(
        std::unique_ptr<ProcessManager>& process,
        uintptr_t address,
        size_t maxOffset,
        std::function<bool(uintptr_t, uintptr_t)> callback,
        std::optional<std::unordered_set<uintptr_t>> visitedCache = std::nullopt,
        uintptr_t depth = 0
    ) {
        std::unordered_set<uintptr_t> cache = visitedCache.value_or(std::unordered_set<uintptr_t>());
        if (cache.contains(address)) {
            return;
        }
        for (size_t offset = 0; offset < maxOffset; offset += 8) {
            if (!ModuleUtils::isValidAddress(process, address + offset)) {
                continue;
            }

            uintptr_t pointer = process->memoryManager.read<uintptr_t>(address + offset);

            if (!ModuleUtils::isValidAddress(process, pointer)) {
                continue;
            }
            if (!callback(pointer, depth)) {
                return;
            }
            recursivePointerWalk(process, pointer, 0x200, callback, cache, depth + 1);
            cache.emplace(pointer);
        }
    }

    static uintptr_t getFirstAncestor(std::unique_ptr<ProcessManager>& process, uintptr_t address) {
        uintptr_t previousObject = 0;
        uintptr_t currentObject = process->memoryManager.read<uintptr_t>(address + 0x50);

        while (currentObject != 0) {
            previousObject = currentObject;
            currentObject = process->memoryManager.read<uintptr_t>(currentObject + 0x50);
        }

        return previousObject;
    }

    static uintptr_t findDatamodelPointer(std::unique_ptr<ProcessManager>& process, uintptr_t tid) {
        uintptr_t dataModel = 0;

        recursivePointerWalk(process, tid, 22160, [&](uintptr_t address, uintptr_t depth) -> bool {
            if (dataModel) {
                return false;
            }

            auto rttiName = RTTIUtils::getRTTIName(process, address);
            if (rttiName.has_value()) {
                std::string& name = rttiName.value();
                if (name == "RBX::ModuleScript" || name == "RBX::LocalScript" || name == "RBX::Folder") {
                    uintptr_t ancestor = getFirstAncestor(process, address);

                    auto ancestorRtti = RTTIUtils::getRTTIName(process, ancestor);
                    if (!ancestorRtti.has_value()) {
                        return true;
                    }
                    if (ancestorRtti.value() == "RBX::DataModel") {
                        dataModel = ancestor;
                        return false;
                    }
                }
            }

            // Limit search depth
            return (depth <= 5);
            }, std::nullopt);

        // Retry
        if (!dataModel) {
            return findDatamodelPointer(process, tid);
        }

        return dataModel;
    }
};


namespace Tasks {
    inline uintptr_t GetDataModel() {
        std::unique_ptr<ProcessManager> process = nullptr;
        do {
            process = ProcessManager::open("RobloxPlayerBeta.exe");

            if (!process) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        } while (!process);
        std::string logPath = std::string(getenv("LOCALAPPDATA")) + "\\Roblox\\logs";
        std::optional<std::string> logFile = LogFileUtils::getLatestLogFile(logPath);

        if (!logFile.has_value()) {
            return 1;
        }
        return ObjectTraverser::findDatamodelPointer(
            process,
            ThreadIdentifier::locateTid(LogFileUtils::readFile(logFile.value()))
        );
    }
    inline std::string getCurrentDate() {
        auto now = std::chrono::system_clock::now();
        std::time_t t_now = std::chrono::system_clock::to_time_t(now);
        std::tm* tm_now = std::localtime(&t_now);

        std::ostringstream oss;
        oss << std::put_time(tm_now, "%H:%M-%m/%d/%y");
        return oss.str();
    }
    using namespace Offsets;
    inline void saveOffsetsToFile() {
        std::ofstream file("Offsets.hpp");
        if (!file.is_open()) {
            std::cerr << xorstr_("[-] Failed to open Offsets.hpp for writing") << std::endl;
            return;
        }

        file << xorstr_("#pragma once\n");
        file << xorstr_("#include <Windows.h>\n");
        file << xorstr_("#include <iostream>\n\n");

        file << xorstr_("namespace Offsets {\n");
        file << xorstr_("    // Dumped by CloudyDumper[RUNTIME] (") << getCurrentDate() << xorstr_(")\n");
        file << xorstr_("    inline constexpr uintptr_t name = 0x") << std::hex << offsets.name << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t placeid = 0x") << std::hex << offsets.placeid << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t workspace = 0x") << std::hex << offsets.workspace << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t parent = 0x") << std::hex << offsets.parent << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t classdescriptor = 0x") << std::hex << offsets.classdescriptor << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t children = 0x") << std::hex << offsets.children << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t childrenend = 0x") << std::hex << offsets.childrenend << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t loaded = 0x") << std::hex << offsets.loaded << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t camera = 0x") << std::hex << offsets.camera << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t localplayer = 0x") << std::hex << offsets.localplayer << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t JumpPower = 0x") << std::hex << offsets.JumpPower << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t walkspeedA = 0x") << std::hex << offsets.walkspeedA << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t walkspeedB = 0x") << std::hex << offsets.walkspeedB << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t gravity = 0x") << std::hex << offsets.gravity << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t health = 0x") << std::hex << offsets.health << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t fov = 0x") << std::hex << offsets.fov << xorstr_(";\n");
        file << xorstr_("    inline constexpr uintptr_t userid = 0x") << std::hex << (offsets.userid + 0x10) << xorstr_(";\n");
        file << xorstr_("}\n");

        file.close();
        std::cout << xorstr_("[+] Offsets saved to Offsets.hpp") << std::endl;
    }
}

// Initialization
namespace init {
    inline void Setup() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &entry)) {
            do {
                if (strcmp(entry.szExeFile, "RobloxPlayerBeta.exe") == 0) {
                    Globals::state.processId = entry.th32ProcessID;
                    Globals::state.processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Globals::state.processId);
                    Globals::state.windowHandle = FindWindowA(NULL, "Roblox");
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
    }
}