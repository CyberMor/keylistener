/*
    This is a KeyListener project file
    Developer: CyberMor <cyber.mor.2020@gmail.com>

    See more here https://github.com/CyberMor/keylistener

    Copyright (c) Daniel (CyberMor) 2020 All rights reserved
*/

#pragma once

#include <types.hpp>
#include <jump_hook.hpp>
#include <scanner.hpp>

#include "raknet/bitstream.h"
#include "raknet/rakclient.h"

struct Network {

    Network(const Network&) = delete;
    Network(Network&&) = delete;
    Network& operator=(const Network&) = delete;
    Network& operator=(Network&&) = delete;

private:

    Network() noexcept = default;
    ~Network() noexcept = default;

public:

    static Network& Instance() noexcept
    {
        static Network instance;
        return instance;
    }

public:

    bool Initialize(const cptr_t base) noexcept
    {
        static const char kGetRakClientInterfacePattern[] =
            "\x50\x00\x00\x00\x00\x00\x00\x00\x51\x68\x00\x00\x00\x00\xE8\x00\x00\x00"
            "\x00\x83\xC4\x04\x89\x04\x24\x85\xC0\xC7\x44\x00\x00\x00\x00\x00\x00\x74\x1F";
        static const char kGetRakClientInterfaceMask[] =
            "x???????xx????x????xxxxxxxxxx??????xx";

        const auto [address, length] = GetModuleInfo(base);
        if (address == nullptr) return false;

        const auto pointer = Scanner(address, length).Find
            (kGetRakClientInterfacePattern, kGetRakClientInterfaceMask);
        if (pointer == nullptr) return false;

        return _hook_getrakclientinterface.Initialize
            (static_cast<adr_t>(pointer) - 13, GetRakClientInterfaceHook);
    }

    void Deinitialize() noexcept
    {
        _hook_getrakclientinterface.Deinitialize();

        _rakclientinterface = nullptr;
    }

public:

    bool SendPacket(const adr_t data, const uint_t size) noexcept
    {
        assert(_rakclientinterface != nullptr);
        return _rakclientinterface->Send(&BitStream(data, size, false),
            PacketPriority::MEDIUM_PRIORITY, PacketReliability::RELIABLE_ORDERED, 0);
    }

private:

    static void GetRakClientInterfaceHook() noexcept;

private:

    RakClientInterface* _rakclientinterface = nullptr;

    JumpHook _hook_getrakclientinterface;

};

void __declspec(naked) Network::GetRakClientInterfaceHook() noexcept
{
    static ptr_t temporary_buffer;

    __asm
    {
        pushad
        mov ebp, esp
        sub esp, __LOCAL_SIZE
    }

    temporary_buffer = Instance()._hook_getrakclientinterface.Address();
    Instance()._hook_getrakclientinterface.Deinitialize();

    temporary_buffer = Instance()._rakclientinterface =
        static_cast<RakClientInterface * (*)()>(temporary_buffer)();

    __asm
    {
        mov esp, ebp
        popad
        mov eax, temporary_buffer
        ret
    }
}
