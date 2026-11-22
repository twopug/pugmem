#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace pug {

struct moduleInfo
{
    std::string name;
    std::uintptr_t base;
    std::size_t size;
};

struct exportInfo
{
    std::string name;
    std::uintptr_t address;
};

class process final
{
public:
    process() = default;
    ~process();

    process(process&& other) noexcept;
    process& operator=(process&& other) noexcept;

    process(const process&) = delete;
    process& operator=(const process&) = delete;

    bool attach(std::string_view name);
    void detach();

    [[nodiscard]] bool valid() const;
    [[nodiscard]] std::uint32_t id() const;
    [[nodiscard]] HANDLE handle() const;

    [[nodiscard]] std::uintptr_t module(std::string_view name) const;
    [[nodiscard]] std::size_t moduleSize(std::string_view name) const;
    [[nodiscard]] std::vector<moduleInfo> modules() const;
    [[nodiscard]] std::vector<exportInfo> exports(std::string_view moduleName) const;
    [[nodiscard]] std::uintptr_t exportAddress(std::string_view moduleName, std::string_view exportName) const;

    [[nodiscard]] bool read(std::uintptr_t address, void* buffer, std::size_t size) const;
    [[nodiscard]] bool write(std::uintptr_t address, const void* buffer, std::size_t size) const;

    template <typename T>
    [[nodiscard]] T read(std::uintptr_t address) const
    {
        static_assert(std::is_trivially_copyable_v<T>, "read requires a trivially copyable type");

        T value{};
        static_cast<void>(read(address, &value, sizeof(T)));
        return value;
    }

    template <typename T>
    [[nodiscard]] bool write(std::uintptr_t address, const T& value) const
    {
        static_assert(std::is_trivially_copyable_v<T>, "write requires a trivially copyable type");

        return write(address, &value, sizeof(T));
    }

    template <typename T>
    [[nodiscard]] T read(std::uintptr_t address, std::initializer_list<std::ptrdiff_t> chain) const
    {
        for (const auto offset : chain)
        {
            address = read<std::uintptr_t>(address + offset);
        }

        return read<T>(address);
    }

    template <typename T>
    [[nodiscard]] T read(std::string_view moduleName, std::ptrdiff_t offset) const
    {
        return read<T>(module(moduleName) + offset);
    }

    template <typename T>
    [[nodiscard]] T read(std::string_view moduleName, std::ptrdiff_t offset, std::initializer_list<std::ptrdiff_t> chain) const
    {
        return read<T>(module(moduleName) + offset, chain);
    }

    template <typename T>
    [[nodiscard]] bool write(std::string_view moduleName, std::ptrdiff_t offset, const T& value) const
    {
        return write<T>(module(moduleName) + offset, value);
    }

    [[nodiscard]] bool directRead(std::uintptr_t address, void* buffer, std::size_t size) const;
    [[nodiscard]] bool directWrite(std::uintptr_t address, const void* buffer, std::size_t size) const;

    template <typename T>
    [[nodiscard]] T directRead(std::uintptr_t address) const
    {
        static_assert(std::is_trivially_copyable_v<T>, "directRead requires a trivially copyable type");

        T value{};
        static_cast<void>(directRead(address, &value, sizeof(T)));
        return value;
    }

    template <typename T>
    [[nodiscard]] bool directWrite(std::uintptr_t address, const T& value) const
    {
        static_assert(std::is_trivially_copyable_v<T>, "directWrite requires a trivially copyable type");

        return directWrite(address, &value, sizeof(T));
    }

    template <typename T>
    [[nodiscard]] T directRead(std::uintptr_t address, std::initializer_list<std::ptrdiff_t> chain) const
    {
        for (const auto offset : chain)
        {
            address = directRead<std::uintptr_t>(address + offset);
        }

        return directRead<T>(address);
    }

    template <typename T>
    [[nodiscard]] T directRead(std::string_view moduleName, std::ptrdiff_t offset) const
    {
        return directRead<T>(module(moduleName) + offset);
    }

    template <typename T>
    [[nodiscard]] T directRead(std::string_view moduleName, std::ptrdiff_t offset, std::initializer_list<std::ptrdiff_t> chain) const
    {
        return directRead<T>(module(moduleName) + offset, chain);
    }

    template <typename T>
    [[nodiscard]] bool directWrite(std::string_view moduleName, std::ptrdiff_t offset, const T& value) const
    {
        return directWrite<T>(module(moduleName) + offset, value);
    }

    [[nodiscard]] std::string readString(std::uintptr_t address) const;
    [[nodiscard]] std::string readString(std::string_view moduleName, std::ptrdiff_t offset) const;

    [[nodiscard]] std::uintptr_t allocate(std::size_t size, std::uint32_t protection = PAGE_EXECUTE_READWRITE) const;
    [[nodiscard]] std::uintptr_t allocate(std::size_t size, std::uint32_t protection, std::size_t* allocated) const;
    [[nodiscard]] bool free(std::uintptr_t address) const;
    [[nodiscard]] bool protect(std::uintptr_t address, std::size_t size, std::uint32_t protection, std::uint32_t* previous = nullptr) const;

    [[nodiscard]] bool execute(std::uintptr_t address, void* parameter = nullptr) const;

private:
    std::wstring readWideString(const UNICODE_STRING& value) const;

    HANDLE processHandle = nullptr;
    std::uint32_t processId = 0;
};

}