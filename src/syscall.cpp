#include "pugmem/syscall.hpp"

#include <algorithm>
#include <cstring>
#include <intrin.h>
#include <iterator>
#include <type_traits>
#include <vector>

namespace pug::syscall {
namespace {

constexpr std::uint8_t stubPrefix[]{ 0x4C, 0x8B, 0xD1, 0xB8 };
constexpr std::size_t stubSize = 0x20;
constexpr NTSTATUS statusProcedureNotFound = static_cast<NTSTATUS>(0xC000007AL);

constexpr std::uint8_t directTemplate[]{
    0x4C, 0x8B, 0xD1,
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    0xC3
};

constexpr std::uint8_t indirectTemplate[]{
    0x4C, 0x8B, 0xD1,
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

constexpr std::size_t indirectTargetOffset = 14;

mode currentMode = mode::indirect;

struct exportInfo
{
    std::uintptr_t address;
    std::string_view name;
};

struct ldrDataTableEntry
{
    LIST_ENTRY inLoadOrderLinks;
    LIST_ENTRY inMemoryOrderLinks;
    LIST_ENTRY inInitializationOrderLinks;
    void* dllBase;
    void* entryPoint;
    ULONG sizeOfImage;
    UNICODE_STRING fullDllName;
    UNICODE_STRING baseDllName;
};

bool equalsIgnoreCase(const UNICODE_STRING& value, const wchar_t* text, std::size_t length)
{
    if (value.Length / sizeof(wchar_t) != length)
    {
        return false;
    }

    for (std::size_t i = 0; i < length; ++i)
    {
        auto left = value.Buffer[i];
        auto right = text[i];

        if (left >= L'A' && left <= L'Z')
        {
            left = static_cast<wchar_t>(left + 32);
        }

        if (right >= L'A' && right <= L'Z')
        {
            right = static_cast<wchar_t>(right + 32);
        }

        if (left != right)
        {
            return false;
        }
    }

    return true;
}

std::uint8_t* ntdllBase()
{
    const auto peb = reinterpret_cast<std::uint8_t*>(__readgsqword(0x60));
    const auto ldr = *reinterpret_cast<std::uint8_t**>(peb + 0x18);
    const auto head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x10);

    for (auto link = head->Flink; link != head; link = link->Flink)
    {
        const auto entry = reinterpret_cast<ldrDataTableEntry*>(link);

        if (equalsIgnoreCase(entry->baseDllName, L"ntdll.dll", 9))
        {
            return static_cast<std::uint8_t*>(entry->dllBase);
        }
    }

    return nullptr;
}

std::vector<exportInfo> loadExports()
{
    std::vector<exportInfo> exports;

    auto* base = ntdllBase();
    if (base == nullptr)
    {
        return exports;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    const auto* exportDirectory =
        reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + directory.VirtualAddress);

    const auto* names = reinterpret_cast<const std::uint32_t*>(base + exportDirectory->AddressOfNames);
    const auto* ordinals = reinterpret_cast<const std::uint16_t*>(base + exportDirectory->AddressOfNameOrdinals);
    const auto* functions = reinterpret_cast<const std::uint32_t*>(base + exportDirectory->AddressOfFunctions);

    exports.reserve(exportDirectory->NumberOfNames);

    for (std::uint32_t i = 0; i < exportDirectory->NumberOfNames; ++i)
    {
        const auto* name = reinterpret_cast<const char*>(base + names[i]);
        const auto* address = base + functions[ordinals[i]];
        exports.push_back({ reinterpret_cast<std::uintptr_t>(address), name });
    }

    std::sort(exports.begin(), exports.end(), [](const exportInfo& left, const exportInfo& right) {
        return left.address < right.address;
    });

    return exports;
}

const std::vector<exportInfo>& exports()
{
    static const auto list = loadExports();
    return list;
}

std::uintptr_t exportAddress(std::string_view functionName)
{
    const auto& list = exports();

    const auto target = std::find_if(list.begin(), list.end(), [functionName](const exportInfo& entry) {
        return entry.name == functionName;
    });

    return target == list.end() ? 0 : target->address;
}

std::optional<std::uint32_t> stubNumber(std::uintptr_t address)
{
    std::uint8_t bytes[8]{};
    std::memcpy(bytes, reinterpret_cast<const void*>(address), sizeof(bytes));

    if (std::memcmp(bytes, stubPrefix, sizeof(stubPrefix)) != 0)
    {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(bytes[4])
        | (static_cast<std::uint32_t>(bytes[5]) << 8)
        | (static_cast<std::uint32_t>(bytes[6]) << 16)
        | (static_cast<std::uint32_t>(bytes[7]) << 24);
}

std::uint8_t* page()
{
    static std::uint8_t* memory = [] {
        using allocateFn = NTSTATUS(NTAPI*)(HANDLE, void**, std::uintptr_t, std::size_t*, std::uint32_t, std::uint32_t);

        const auto address = exportAddress("NtAllocateVirtualMemory");
        if (address == 0)
        {
            return static_cast<std::uint8_t*>(nullptr);
        }

        void* base = nullptr;
        std::size_t size = 0x1000;

        const auto status = reinterpret_cast<allocateFn>(address)(
            reinterpret_cast<HANDLE>(-1),
            &base,
            0,
            &size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        return NT_SUCCESS(status) ? static_cast<std::uint8_t*>(base) : static_cast<std::uint8_t*>(nullptr);
    }();

    return memory;
}

std::uintptr_t syscallInstruction(std::string_view functionName)
{
    const auto address = exportAddress(functionName);
    if (address == 0)
    {
        return 0;
    }

    const auto* bytes = reinterpret_cast<const std::uint8_t*>(address);

    for (std::size_t i = 0; i < stubSize; ++i)
    {
        if (bytes[i] == 0x0F && bytes[i + 1] == 0x05)
        {
            return address + i;
        }
    }

    return 0;
}

stub buildStub(std::uint32_t ssn, std::string_view functionName)
{
    static std::size_t used = 0;

    auto* memory = page();
    if (memory == nullptr)
    {
        return nullptr;
    }

    const auto target = currentMode == mode::indirect ? syscallInstruction(functionName) : 0;
    const auto useIndirect = target != 0;

    const auto size = useIndirect ? sizeof(indirectTemplate) : sizeof(directTemplate);

    auto* slot = memory + used;
    used += size;

    if (useIndirect)
    {
        std::memcpy(slot, indirectTemplate, sizeof(indirectTemplate));
        std::memcpy(slot + 4, &ssn, sizeof(ssn));
        std::memcpy(slot + indirectTargetOffset, &target, sizeof(target));
    }
    else
    {
        std::memcpy(slot, directTemplate, sizeof(directTemplate));
        std::memcpy(slot + 4, &ssn, sizeof(ssn));
    }

    return reinterpret_cast<stub>(slot);
}

template <std::size_t N>
struct fixedString
{
    char value[N]{};

    constexpr fixedString(const char (&text)[N])
    {
        std::copy_n(text, N, value);
    }

    constexpr operator std::string_view() const
    {
        return { value, N - 1 };
    }
};

template <fixedString Name>
stub entry()
{
    static const auto resolved = resolve(Name);
    return resolved;
}

template <fixedString Name>
stub directEntry()
{
    static const auto resolved = [] {
        const auto previous = currentMode;
        currentMode = mode::direct;
        const auto result = resolve(Name);
        currentMode = previous;
        return result;
    }();

    return resolved;
}

template <typename T>
std::uintptr_t asArg(T value)
{
    if constexpr (std::is_pointer_v<T>)
    {
        return reinterpret_cast<std::uintptr_t>(value);
    }
    else
    {
        return static_cast<std::uintptr_t>(value);
    }
}

}

std::optional<std::uint32_t> number(std::string_view functionName)
{
    const auto& list = exports();

    const auto target = std::find_if(list.begin(), list.end(), [functionName](const exportInfo& entry) {
        return entry.name == functionName;
    });

    if (target == list.end())
    {
        return std::nullopt;
    }

    if (const auto ssn = stubNumber(target->address))
    {
        return ssn;
    }

    for (auto previous = std::make_reverse_iterator(target); previous != list.rend(); ++previous)
    {
        const auto ssn = stubNumber(previous->address);
        if (!ssn)
        {
            continue;
        }

        const auto distance = target->address - previous->address;
        if (distance % stubSize != 0)
        {
            return std::nullopt;
        }

        return *ssn + static_cast<std::uint32_t>(distance / stubSize);
    }

    return std::nullopt;
}

void setMode(mode value)
{
    currentMode = value;
}

mode getMode()
{
    return currentMode;
}

stub resolve(std::string_view functionName)
{
    const auto ssn = number(functionName);
    if (!ssn)
    {
        return nullptr;
    }

    return buildStub(*ssn, functionName);
}

NTSTATUS readVirtualMemory(HANDLE process, void* base, void* buffer, std::size_t size, std::size_t* bytesRead)
{
    const auto fn = entry<"NtReadVirtualMemory">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(base), asArg(buffer), asArg(size), asArg(bytesRead), 0);
}

NTSTATUS directReadVirtualMemory(HANDLE process, void* base, void* buffer, std::size_t size, std::size_t* bytesRead)
{
    const auto fn = directEntry<"NtReadVirtualMemory">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(base), asArg(buffer), asArg(size), asArg(bytesRead), 0);
}

NTSTATUS writeVirtualMemory(HANDLE process, void* base, const void* buffer, std::size_t size, std::size_t* bytesWritten)
{
    const auto fn = entry<"NtWriteVirtualMemory">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(base), asArg(buffer), asArg(size), asArg(bytesWritten), 0);
}

NTSTATUS directWriteVirtualMemory(HANDLE process, void* base, const void* buffer, std::size_t size, std::size_t* bytesWritten)
{
    const auto fn = directEntry<"NtWriteVirtualMemory">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(base), asArg(buffer), asArg(size), asArg(bytesWritten), 0);
}

NTSTATUS openProcess(HANDLE* process, ACCESS_MASK access, OBJECT_ATTRIBUTES* attributes, CLIENT_ID* clientId)
{
    const auto fn = entry<"NtOpenProcess">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(access), asArg(attributes), asArg(clientId), 0, 0);
}

NTSTATUS close(HANDLE handle)
{
    const auto fn = entry<"NtClose">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(asArg(handle), 0, 0, 0, 0, 0);
}

NTSTATUS allocateVirtualMemory(HANDLE process, void** base, std::uintptr_t zeroBits, std::size_t* size, std::uint32_t type, std::uint32_t protection)
{
    const auto fn = entry<"NtAllocateVirtualMemory">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(base), asArg(zeroBits), asArg(size), asArg(type), asArg(protection));
}

NTSTATUS protectVirtualMemory(HANDLE process, void** base, std::size_t* size, std::uint32_t protection, std::uint32_t* previous)
{
    const auto fn = entry<"NtProtectVirtualMemory">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(base), asArg(size), asArg(protection), asArg(previous), 0);
}

NTSTATUS freeVirtualMemory(HANDLE process, void** base, std::size_t* size, std::uint32_t type)
{
    const auto fn = entry<"NtFreeVirtualMemory">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(base), asArg(size), asArg(type), 0, 0);
}

NTSTATUS querySystemInformation(std::uint32_t infoClass, void* buffer, std::size_t size, std::size_t* returned)
{
    const auto fn = entry<"NtQuerySystemInformation">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(infoClass), asArg(buffer), asArg(size), asArg(returned), 0, 0);
}

NTSTATUS queryInformationProcess(HANDLE process, std::uint32_t infoClass, void* buffer, std::size_t size, std::size_t* returned)
{
    const auto fn = entry<"NtQueryInformationProcess">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(
        asArg(process), asArg(infoClass), asArg(buffer), asArg(size), asArg(returned), 0);
}

NTSTATUS createThread(HANDLE* thread, ACCESS_MASK access, OBJECT_ATTRIBUTES* attributes, HANDLE process, void* start, void* parameter, std::uint32_t flags)
{
    using wideStub = NTSTATUS (*)(
        std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t,
        std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t,
        std::uintptr_t, std::uintptr_t, std::uintptr_t);

    const auto fn = entry<"NtCreateThreadEx">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return reinterpret_cast<wideStub>(fn)(
        asArg(thread), asArg(access), asArg(attributes), asArg(process),
        asArg(start), asArg(parameter), asArg(flags), 0, 0, 0, 0);
}

NTSTATUS waitForSingleObject(HANDLE handle, std::int64_t timeout, std::uint32_t alertable)
{
    const auto fn = entry<"NtWaitForSingleObject">();
    if (fn == nullptr)
    {
        return statusProcedureNotFound;
    }

    return fn(asArg(handle), asArg(timeout), asArg(alertable), 0, 0, 0);
}

}