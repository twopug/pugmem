#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace pug {

class process;

class pattern final
{
public:
    explicit pattern(std::string_view text);

    [[nodiscard]] bool valid() const;
    [[nodiscard]] std::size_t size() const;

    [[nodiscard]] std::optional<std::uintptr_t> find(const process& target, std::uintptr_t start, std::size_t length) const;
    [[nodiscard]] std::optional<std::uintptr_t> find(const process& target, std::string_view moduleName) const;

private:
    struct element
    {
        std::uint8_t value;
        std::uint8_t mask;
    };

    std::vector<element> elements;
};

}