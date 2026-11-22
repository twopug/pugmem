#include "pugmem/process.hpp"

#include "pugmem/syscall.hpp"

#include <cctype>
#include <string>
#include <cwctype>
#include <vector>

namespace pug::process_detail {

constexpr std::uint32_t systemProcessInformationClass = 5;
constexpr std::uint32_t processBasicInformationClass = 0;

constexpr NTSTATUS statusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

struct systemProcessInformationEntry
{
    ULONG nextEntryOffset;
    ULONG numberOfThreads;
    LARGE_INTEGER workingSetPrivateSize;
    ULONG hardFaultCount;
    ULONG numberOfThreadsHighWatermark;
    ULONGLONG cycleTime;
    LARGE_INTEGER createTime;
    LARGE_INTEGER userTime;
    LARGE_INTEGER kernelTime;
    UNICODE_STRING imageName;
    LONG basePriority;
    HANDLE uniqueProcessId;
};

struct processBasicInfo
{
    NTSTATUS exitStatus;
    void* pebBaseAddress;
    std::uintptr_t affinityMask;
    LONG basePriority;
    HANDLE uniqueProcessId;
    HANDLE inheritedFromUniqueProcessId;
};

struct peb
{
    std::uint8_t reserved[0x18];
    void* ldr;
};

struct pebLdrData
{
    std::uint8_t reserved[0x10];
    LIST_ENTRY inLoadOrderModuleList;
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

std::wstring_view wideView(const UNICODE_STRING& value)
{
    if (value.Buffer == nullptr)
    {
        return {};
    }

    return { value.Buffer, value.Length / sizeof(wchar_t) };
}

bool equalsIgnoreCase(std::string_view left, std::string_view right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (std::size_t i = 0; i < left.size(); ++i)
    {
        if (std::tolower(static_cast<unsigned char>(left[i]))
            != std::tolower(static_cast<unsigned char>(right[i])))
        {
            return false;
        }
    }

    return true;
}

bool equalsIgnoreCase(std::wstring_view wide, std::string_view narrow)
{
    if (wide.size() != narrow.size())
    {
        return false;
    }

    for (std::size_t i = 0; i < narrow.size(); ++i)
    {
        const auto left = static_cast<wchar_t>(std::tolower(static_cast<unsigned char>(narrow[i])));
        const auto right = static_cast<wchar_t>(std::towlower(wide[i]));

        if (left != right)
        {
            return false;
        }
    }

    return true;
}

}

namespace pug {

process::~process()
{
    detach();
}

process::process(process&& other) noexcept
    : processHandle(other.processHandle)
    , processId(other.processId)
{
    other.processHandle = nullptr;
    other.processId = 0;
}

process& process::operator=(process&& other) noexcept
{
    if (this != &other)
    {
        detach();

        processHandle = other.processHandle;
        processId = other.processId;

        other.processHandle = nullptr;
        other.processId = 0;
    }

    return *this;
}

bool process::attach(std::string_view name)
{
    detach();

    std::vector<std::uint8_t> buffer(0x10000);
    std::size_t returned = 0;

    NTSTATUS status = process_detail::statusInfoLengthMismatch;
    while (status == process_detail::statusInfoLengthMismatch)
    {
        status = syscall::querySystemInformation(
            process_detail::systemProcessInformationClass,
            buffer.data(),
            buffer.size(),
            &returned);

        if (status == process_detail::statusInfoLengthMismatch)
        {
            buffer.resize(buffer.size() * 2);
        }
    }

    if (!NT_SUCCESS(status))
    {
        return false;
    }

    auto* entry = reinterpret_cast<process_detail::systemProcessInformationEntry*>(buffer.data());
    while (true)
    {
        if (process_detail::equalsIgnoreCase(process_detail::wideView(entry->imageName), name))
        {
            processId = static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(entry->uniqueProcessId));
            break;
        }

        if (entry->nextEntryOffset == 0)
        {
            return false;
        }

        entry = reinterpret_cast<process_detail::systemProcessInformationEntry*>(
            reinterpret_cast<std::uint8_t*>(entry) + entry->nextEntryOffset);
    }

    CLIENT_ID clientId{};
    clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(processId));

    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(OBJECT_ATTRIBUTES);

    status = syscall::openProcess(&processHandle, PROCESS_ALL_ACCESS, &attributes, &clientId);
    if (!NT_SUCCESS(status))
    {
        processHandle = nullptr;
        processId = 0;
        return false;
    }

    return true;
}

void process::detach()
{
    if (processHandle != nullptr)
    {
        static_cast<void>(syscall::close(processHandle));
    }

    processHandle = nullptr;
    processId = 0;
}

bool process::valid() const
{
    return processHandle != nullptr;
}

std::uint32_t process::id() const
{
    return processId;
}

HANDLE process::handle() const
{
    return processHandle;
}

std::vector<moduleInfo> process::modules() const
{
    std::vector<moduleInfo> result;

    if (!valid())
    {
        return result;
    }

    process_detail::processBasicInfo basic{};
    std::size_t returned = 0;

    const auto status = syscall::queryInformationProcess(
        processHandle,
        process_detail::processBasicInformationClass,
        &basic,
        sizeof(basic),
        &returned);

    if (!NT_SUCCESS(status) || basic.pebBaseAddress == nullptr)
    {
        return result;
    }

    process_detail::peb peb{};
    if (!read(reinterpret_cast<std::uintptr_t>(basic.pebBaseAddress), &peb, sizeof(peb))
        || peb.ldr == nullptr)
    {
        return result;
    }

    process_detail::pebLdrData ldr{};
    if (!read(reinterpret_cast<std::uintptr_t>(peb.ldr), &ldr, sizeof(ldr)))
    {
        return result;
    }

    const auto head = reinterpret_cast<std::uintptr_t>(peb.ldr)
        + offsetof(process_detail::pebLdrData, inLoadOrderModuleList);

    auto link = reinterpret_cast<std::uintptr_t>(ldr.inLoadOrderModuleList.Flink);

    while (link != 0 && link != head)
    {
        process_detail::ldrDataTableEntry entry{};
        if (!read(link, &entry, sizeof(entry)))
        {
            break;
        }

        const auto name = readWideString(entry.baseDllName);
        if (!name.empty())
        {
            std::string narrow;
            narrow.reserve(name.size());

            for (const auto c : name)
            {
                narrow.push_back(c < 0x80 ? static_cast<char>(c) : '?');
            }

            result.push_back({
                std::move(narrow),
                reinterpret_cast<std::uintptr_t>(entry.dllBase),
                entry.sizeOfImage
            });
        }

        link = reinterpret_cast<std::uintptr_t>(entry.inLoadOrderLinks.Flink);
    }

    return result;
}

std::uintptr_t process::module(std::string_view name) const
{
    for (const auto& entry : modules())
    {
        if (process_detail::equalsIgnoreCase(entry.name, name))
        {
            return entry.base;
        }
    }

    return 0;
}

std::size_t process::moduleSize(std::string_view name) const
{
    for (const auto& entry : modules())
    {
        if (process_detail::equalsIgnoreCase(entry.name, name))
        {
            return entry.size;
        }
    }

    return 0;
}

std::vector<exportInfo> process::exports(std::string_view moduleName) const
{
    std::vector<exportInfo> result;

    const auto base = module(moduleName);
    if (base == 0)
    {
        return result;
    }

    const auto dos = read<IMAGE_DOS_HEADER>(base);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return result;
    }

    const auto nt = read<IMAGE_NT_HEADERS>(base + dos.e_lfanew);
    if (nt.Signature != IMAGE_NT_SIGNATURE)
    {
        return result;
    }

    const auto& directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0 || directory.Size == 0)
    {
        return result;
    }

    const auto exportDirectory = read<IMAGE_EXPORT_DIRECTORY>(base + directory.VirtualAddress);
    if (exportDirectory.NumberOfNames == 0)
    {
        return result;
    }

    std::vector<std::uint32_t> names(exportDirectory.NumberOfNames);
    std::vector<std::uint16_t> ordinals(exportDirectory.NumberOfNames);
    std::vector<std::uint32_t> functions(exportDirectory.NumberOfFunctions);

    if (!read(base + exportDirectory.AddressOfNames, names.data(), names.size() * sizeof(std::uint32_t)))
    {
        return result;
    }

    if (!read(base + exportDirectory.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(std::uint16_t)))
    {
        return result;
    }

    if (!read(base + exportDirectory.AddressOfFunctions, functions.data(), functions.size() * sizeof(std::uint32_t)))
    {
        return result;
    }

    result.reserve(exportDirectory.NumberOfNames);

    for (std::size_t i = 0; i < names.size(); ++i)
    {
        char nameBuffer[256]{};
        if (!read(base + names[i], nameBuffer, sizeof(nameBuffer) - 1))
        {
            continue;
        }

        const std::string name(nameBuffer);
        if (name.empty())
        {
            continue;
        }

        const auto ordinal = ordinals[i];
        if (ordinal >= functions.size())
        {
            continue;
        }

        result.push_back({ name, base + functions[ordinal] });
    }

    return result;
}

std::uintptr_t process::exportAddress(std::string_view moduleName, std::string_view exportName) const
{
    for (const auto& entry : exports(moduleName))
    {
        if (entry.name == exportName)
        {
            return entry.address;
        }
    }

    return 0;
}

std::uintptr_t process::allocate(std::size_t size, std::uint32_t protection) const
{
    return allocate(size, protection, nullptr);
}

std::uintptr_t process::allocate(std::size_t size, std::uint32_t protection, std::size_t* allocated) const
{
    if (!valid() || size == 0)
    {
        return 0;
    }

    void* base = nullptr;
    auto regionSize = size;

    const auto status = syscall::allocateVirtualMemory(
        processHandle,
        &base,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        protection);

    if (!NT_SUCCESS(status))
    {
        return 0;
    }

    if (allocated != nullptr)
    {
        *allocated = regionSize;
    }

    return reinterpret_cast<std::uintptr_t>(base);
}

bool process::free(std::uintptr_t address) const
{
    if (!valid() || address == 0)
    {
        return false;
    }

    void* base = reinterpret_cast<void*>(address);
    std::size_t size = 0;

    const auto status = syscall::freeVirtualMemory(processHandle, &base, &size, MEM_RELEASE);

    return NT_SUCCESS(status);
}

bool process::protect(std::uintptr_t address, std::size_t size, std::uint32_t protection, std::uint32_t* previous) const
{
    if (!valid() || address == 0 || size == 0)
    {
        return false;
    }

    void* base = reinterpret_cast<void*>(address);
    auto regionSize = size;
    std::uint32_t old = 0;

    const auto status = syscall::protectVirtualMemory(
        processHandle,
        &base,
        &regionSize,
        protection,
        &old);

    if (previous != nullptr)
    {
        *previous = old;
    }

    return NT_SUCCESS(status);
}

bool process::execute(std::uintptr_t address, void* parameter) const
{
    if (!valid() || address == 0)
    {
        return false;
    }

    HANDLE thread = nullptr;

    const auto status = syscall::createThread(
        &thread,
        THREAD_ALL_ACCESS,
        nullptr,
        processHandle,
        reinterpret_cast<void*>(address),
        parameter,
        0);

    if (!NT_SUCCESS(status))
    {
        return false;
    }

    static_cast<void>(syscall::close(thread));

    return true;
}

bool process::read(std::uintptr_t address, void* buffer, std::size_t size) const
{
    if (!valid() || address == 0 || buffer == nullptr || size == 0)
    {
        return false;
    }

    std::size_t bytesRead = 0;
    const auto status = syscall::readVirtualMemory(
        processHandle,
        reinterpret_cast<void*>(address),
        buffer,
        size,
        &bytesRead);

    return NT_SUCCESS(status) && bytesRead == size;
}

bool process::write(std::uintptr_t address, const void* buffer, std::size_t size) const
{
    if (!valid() || address == 0 || buffer == nullptr || size == 0)
    {
        return false;
    }

    std::size_t bytesWritten = 0;
    const auto status = syscall::writeVirtualMemory(
        processHandle,
        reinterpret_cast<void*>(address),
        buffer,
        size,
        &bytesWritten);

    return NT_SUCCESS(status) && bytesWritten == size;
}

bool process::directRead(std::uintptr_t address, void* buffer, std::size_t size) const
{
    if (!valid() || address == 0 || buffer == nullptr || size == 0)
    {
        return false;
    }

    std::size_t bytesRead = 0;
    const auto status = syscall::directReadVirtualMemory(
        processHandle,
        reinterpret_cast<void*>(address),
        buffer,
        size,
        &bytesRead);

    return NT_SUCCESS(status) && bytesRead == size;
}

bool process::directWrite(std::uintptr_t address, const void* buffer, std::size_t size) const
{
    if (!valid() || address == 0 || buffer == nullptr || size == 0)
    {
        return false;
    }

    std::size_t bytesWritten = 0;
    const auto status = syscall::directWriteVirtualMemory(
        processHandle,
        reinterpret_cast<void*>(address),
        buffer,
        size,
        &bytesWritten);

    return NT_SUCCESS(status) && bytesWritten == size;
}

std::string process::readString(std::uintptr_t address) const
{
    // msvc std::string layout
    const auto length = read<std::int32_t>(address + 0x10);
    if (length <= 0 || length > 0x1000)
    {
        return {};
    }

    const auto capacity = read<std::int32_t>(address + 0x14);
    const auto data = capacity >= 16 ? read<std::uintptr_t>(address) : address;

    std::string result(static_cast<std::size_t>(length), '\0');
    if (!read(data, result.data(), result.size()))
    {
        return {};
    }

    return result;
}

std::string process::readString(std::string_view moduleName, std::ptrdiff_t offset) const
{
    return readString(module(moduleName) + offset);
}

std::wstring process::readWideString(const UNICODE_STRING& value) const
{
    if (value.Buffer == nullptr || value.Length == 0)
    {
        return {};
    }

    std::wstring result(value.Length / sizeof(wchar_t), L'\0');
    if (!read(reinterpret_cast<std::uintptr_t>(value.Buffer), result.data(), value.Length))
    {
        return {};
    }

    return result;
}

}