pugmem

a small x64 windows memory library. it talks to the kernel with direct or indirect
syscalls instead of going through the win32 api so reads and writes skip
the ntdll export and the extra layer above it

how to use

just drop the include/ and src/ folders into your project and add all
three cpp files to your build then include the umbrella header

    #include "pugmem/pugmem.hpp"

    if (!pug::memory.attach("game.exe"))
        return 1;

    const auto base = pug::memory.module("game.exe");

    int health = pug::memory.read<int>(base + 0x1234);
    pug::memory.write(base + 0x1234, 100);

    // follow a pointer chain
    int ammo = pug::memory.read<int>(base + 0x10, { 0x8, 0x1C });

    // read an msvc std::string
    std::string name = pug::memory.readString(base + 0x2000);

if you would rather not use the global make your own:

    pug::process target;
    target.attach("game.exe");

reading and writing

every read and write has a direct variant. indirect is the default and
jumps into ntdll so the call stack looks legitimate. direct executes the
syscall from our own memory which is faster but easier to spot

    pug::memory.read<T>(addr)          indirect
    pug::memory.directRead<T>(addr)    direct

    pug::memory.write<T>(addr, value)  indirect
    pug::memory.directWrite<T>(addr, value)  direct

both take the same arguments so you can swap them freely

    pug::memory.read<int>(base + 0x1234)
    pug::memory.directRead<int>(base + 0x1234)

    pug::memory.read<int>("game.exe", 0x1234)
    pug::memory.directRead<int>("game.exe", 0x1234)

    pug::memory.read<int>(base + 0x10, { 0x8, 0x1C })
    pug::memory.directRead<int>(base + 0x10, { 0x8, 0x1C })

    pug::memory.read<int>("game.exe", 0x10, { 0x8, 0x1C })
    pug::memory.directRead<int>("game.exe", 0x10, { 0x8, 0x1C })

you can also flip the default for everything

    pug::syscall::setMode(pug::syscall::mode::direct);
    pug::syscall::setMode(pug::syscall::mode::indirect);

api

    attach(name)              attach to a process by exe name
    detach()                  close the handle
    valid()                   true if attached
    id()                      process id
    handle()                  raw handle

    module(name)              base address of a loaded module
    moduleSize(name)          size of a loaded module
    modules()                 every loaded module as {name, base, size}
    exports(module)           every export as {name, address}
    exportAddress(mod, name)  address of one export

    read<T>(addr)             read a value
    read<T>(addr, {...})      read through a pointer chain
    read<T>(mod, off)         read at module + offset
    read<T>(mod, off, {...})  read at module + offset through a chain
    read(addr, buf, size)     read raw bytes
    write<T>(addr, value)     write a value
    write<T>(mod, off, value) write at module + offset
    write(addr, buf, size)    write raw bytes

    directRead / directWrite  same overloads as read and write

    readString(addr)          read an msvc std::string
    readString(mod, off)      read an msvc std::string at module + offset

    allocate(size, prot)      reserve memory in the target
    allocate(size, prot, &n)  same but reports the real size
    free(addr)                release memory
    protect(addr, size, prot) change protection
    execute(addr, param)      start a thread at addr

pattern scanning

ida style signatures with ?? wildcards

    pug::pattern signature("48 8B ?? ?? 89");

    if (const auto found = signature.find(pug::memory, "game.exe"))
        std::printf("0x%llX\n", *found);

you can also scan a raw range

    signature.find(pug::memory, start, length);

notes

- x64 only msvc v143 or newer c++20 i may make something for x86 later
- syscall numbers are resolved from ntdll at runtime nothing hardcoded
- indirect is the default direct is available per call
- readString assumes the msvc std::string layout
- yeah i know msvc :c
- i think this is the least amount of autos ive ever used in a project
- might use in next project i post
- i think this will work on all winvers but i didnt test
- may add hooking later or maybe x86 idk