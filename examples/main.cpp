#include "pugmem/pugmem.hpp"

#include <cstdio>

namespace {

const char* result(bool ok)
{
    return ok ? "ok" : "failed";
}

void printProcess(const char* name)
{
    std::printf("attach\n");
    std::printf("  process  %s\n", name);
    std::printf("  pid      %u\n", pug::memory.id());
    std::printf("  handle   0x%llX\n", static_cast<unsigned long long>(
        reinterpret_cast<std::uintptr_t>(pug::memory.handle())));
    std::printf("\n");
}

void printModule(const char* name)
{
    const auto base = pug::memory.module(name);
    const auto size = pug::memory.moduleSize(name);

    std::printf("module\n");
    std::printf("  name     %s\n", name);
    std::printf("  base     0x%llX\n", static_cast<unsigned long long>(base));
    std::printf("  size     0x%zX (%zu bytes)\n", size, size);
    std::printf("\n");
}

void printExports()
{
    const auto address = pug::memory.exportAddress("kernel32.dll", "CreateFileW");

    std::printf("exports\n");
    std::printf("  CreateFileW  0x%llX  %s\n",
        static_cast<unsigned long long>(address),
        result(address != 0));
    std::printf("\n");
}

void printPattern()
{
    const pug::pattern signature("48 8B ?? ?? 89");
    const auto found = signature.find(pug::memory, "kernel32.dll");

    std::printf("pattern\n");
    std::printf("  signature  48 8B ?? ?? 89\n");
    std::printf("  result     %s\n", found ? "found" : "not found");

    if (found)
    {
        std::printf("  address    0x%llX\n", static_cast<unsigned long long>(*found));
    }

    std::printf("\n");
}

void printAllocation()
{
    std::size_t allocated = 0;
    const auto region = pug::memory.allocate(0x1000, PAGE_EXECUTE_READWRITE, &allocated);

    std::printf("allocation\n");
    std::printf("  result     %s\n", result(region != 0));

    if (region == 0)
    {
        std::printf("\n");
        return;
    }

    std::printf("  address    0x%llX\n", static_cast<unsigned long long>(region));
    std::printf("  size       0x%zX (%zu bytes)\n", allocated, allocated);
    std::printf("\n");

    const std::uint8_t code[]{ 0xC3 };
    const auto wrote = pug::memory.write(region, code, sizeof(code));

    std::printf("write\n");
    std::printf("  result     %s\n", result(wrote));
    std::printf("  bytes      %zu\n", sizeof(code));
    std::printf("\n");

    std::uint8_t readBack = 0;
    const auto read = pug::memory.read(region, &readBack, sizeof(readBack));

    std::printf("read\n");
    std::printf("  result     %s\n", result(read));
    std::printf("  value      0x%02X\n", readBack);
    std::printf("\n");

    const auto executed = pug::memory.execute(region);

    std::printf("execute\n");
    std::printf("  result     %s\n", result(executed));
    std::printf("\n");

    const auto freed = pug::memory.free(region);

    std::printf("free\n");
    std::printf("  result     %s\n", result(freed));
    std::printf("\n");
}

void printDirectRead(const char* name)
{
    const auto base = pug::memory.module(name);

    const auto plain = pug::memory.directRead<IMAGE_DOS_HEADER>(base);
    const auto byModule = pug::memory.directRead<IMAGE_DOS_HEADER>(name, 0);
    const auto peOffset = pug::memory.directRead<std::int32_t>(name, 0x3C);

    std::printf("direct read\n");
    std::printf("  mode       direct\n");
    std::printf("  DOS header 0x%X\n", plain.e_magic);
    std::printf("  by module  0x%X\n", byModule.e_magic);
    std::printf("  pe offset  0x%X\n", peOffset);
    std::printf("\n");
}

}

auto main(int const argc, char const* const* const argv) -> std::conditional_t<std::is_same_v<decltype(0), int>, int, long> // long because aura
{
    const char* name = argc > 1 ? argv[1] : "notepad.exe";

    if (!pug::memory.attach(name))
    {
        std::printf("attach failed: %s\n", name);
        return 1;
    }

    printProcess(name);
    printModule(name);
    printExports();
    printPattern();
    printAllocation();
    printDirectRead(name);

    return 0;
}