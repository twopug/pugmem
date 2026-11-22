#include "pugmem/pattern.hpp"

#include "pugmem/process.hpp"

#include <cctype>
#include <vector>

namespace pug {

namespace {

int hexValue(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }

    return -1;
}

}

pattern::pattern(std::string_view text)
{
    std::size_t i = 0;

    while (i < text.size())
    {
        const auto c = text[i];

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        {
            ++i;
            continue;
        }

        if (c == '?')
        {
            elements.push_back({ 0, 0 });
            ++i;

            if (i < text.size() && text[i] == '?')
            {
                ++i;
            }

            continue;
        }

        if (i + 1 >= text.size())
        {
            elements.clear();
            return;
        }

        const auto high = hexValue(c);
        const auto low = hexValue(text[i + 1]);

        if (high < 0 || low < 0)
        {
            elements.clear();
            return;
        }

        elements.push_back({ static_cast<std::uint8_t>((high << 4) | low), 0xFF });
        i += 2;
    }
}

bool pattern::valid() const
{
    return !elements.empty();
}

std::size_t pattern::size() const
{
    return elements.size();
}

std::optional<std::uintptr_t> pattern::find(const process& target, std::uintptr_t start, std::size_t length) const
{
    if (elements.empty() || length < elements.size())
    {
        return std::nullopt;
    }

    constexpr std::size_t chunkSize = 0x1000;

    std::vector<std::uint8_t> buffer(chunkSize + elements.size());
    const auto last = start + length - elements.size();

    for (auto address = start; address <= last; address += chunkSize)
    {
        const auto span = (last - address) + elements.size();
        const auto readSize = span < buffer.size() ? span : buffer.size();

        if (!target.read(address, buffer.data(), readSize))
        {
            continue;
        }

        for (std::size_t offset = 0; offset + elements.size() <= readSize; ++offset)
        {
            bool matched = true;

            for (std::size_t i = 0; i < elements.size(); ++i)
            {
                if ((buffer[offset + i] & elements[i].mask) != (elements[i].value & elements[i].mask))
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                return address + offset;
            }
        }
    }

    return std::nullopt;
}

std::optional<std::uintptr_t> pattern::find(const process& target, std::string_view moduleName) const
{
    const auto base = target.module(moduleName);
    if (base == 0)
    {
        return std::nullopt;
    }

    const auto size = target.moduleSize(moduleName);
    if (size == 0)
    {
        return std::nullopt;
    }

    return find(target, base, size);
}

}