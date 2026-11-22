#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace pug::syscall {

using stub = NTSTATUS (*)(
    std::uintptr_t a1,
    std::uintptr_t a2,
    std::uintptr_t a3,
    std::uintptr_t a4,
    std::uintptr_t a5,
    std::uintptr_t a6);

enum class mode
{
    indirect,
    direct
};

void setMode(mode value);
[[nodiscard]] mode getMode();

[[nodiscard]] std::optional<std::uint32_t> number(std::string_view functionName);

[[nodiscard]] stub resolve(std::string_view functionName);

[[nodiscard]] NTSTATUS readVirtualMemory(HANDLE process, void* base, void* buffer, std::size_t size, std::size_t* bytesRead);
[[nodiscard]] NTSTATUS directReadVirtualMemory(HANDLE process, void* base, void* buffer, std::size_t size, std::size_t* bytesRead);
[[nodiscard]] NTSTATUS writeVirtualMemory(HANDLE process, void* base, const void* buffer, std::size_t size, std::size_t* bytesWritten);
[[nodiscard]] NTSTATUS directWriteVirtualMemory(HANDLE process, void* base, const void* buffer, std::size_t size, std::size_t* bytesWritten);
[[nodiscard]] NTSTATUS openProcess(HANDLE* process, ACCESS_MASK access, OBJECT_ATTRIBUTES* attributes, CLIENT_ID* clientId);
[[nodiscard]] NTSTATUS close(HANDLE handle);
[[nodiscard]] NTSTATUS allocateVirtualMemory(HANDLE process, void** base, std::uintptr_t zeroBits, std::size_t* size, std::uint32_t type, std::uint32_t protection);
[[nodiscard]] NTSTATUS protectVirtualMemory(HANDLE process, void** base, std::size_t* size, std::uint32_t protection, std::uint32_t* previous);
[[nodiscard]] NTSTATUS freeVirtualMemory(HANDLE process, void** base, std::size_t* size, std::uint32_t type);
[[nodiscard]] NTSTATUS querySystemInformation(std::uint32_t infoClass, void* buffer, std::size_t size, std::size_t* returned);
[[nodiscard]] NTSTATUS queryInformationProcess(HANDLE process, std::uint32_t infoClass, void* buffer, std::size_t size, std::size_t* returned);
[[nodiscard]] NTSTATUS createThread(HANDLE* thread, ACCESS_MASK access, OBJECT_ATTRIBUTES* attributes, HANDLE process, void* start, void* parameter, std::uint32_t flags);
[[nodiscard]] NTSTATUS waitForSingleObject(HANDLE handle, std::int64_t timeout, std::uint32_t alertable);

}