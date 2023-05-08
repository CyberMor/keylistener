/*
    This is a KeyListener project file
    Developer: CyberMor <cyber.mor.2020@gmail.com>

    See more here https://github.com/CyberMor/keylistener

    Copyright (c) Daniel (CyberMor) 2020 All rights reserved
*/

#pragma once

#include <functional>

#include <types.hpp>
#include <unprotect_scope.hpp>
#include <jump_hook.hpp>
#include <scanner.hpp>

#include "raknet/bitstream.h"
#include "raknet/networktypes.h"

#ifdef _WIN32
#define STDCALL  __stdcall
#define THISCALL __thiscall
#else
#define STDCALL
#define THISCALL
#endif

#ifdef _WIN32
constexpr size_t kRaknetReceiveOffset          = 10;
constexpr size_t kRaknetDeallocatePacketOffset = 12;
#else
constexpr size_t kRaknetReceiveOffset          = 11;
constexpr size_t kRaknetDeallocatePacketOffset = 13;
#endif

typedef Packet* (THISCALL* raknet_receive_t)          (ptr_t);
typedef void    (THISCALL* raknet_deallocatepacket_t) (ptr_t, Packet*);

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
#ifdef _WIN32
        static const char kGetRakServerPattern[] =
            "\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x51\x68\x18\x0E\x00\x00\xE8"
            "\xFF\xFF\xFF\xFF\x83\xC4\x04\x89\x04\x24\x85\xC0\xC7\x44\x24\xFF\x00\x00\x00\x00\x74\x16";
        static const char kGetRakServerMask[] =
            "xxxxxxxxxxxxxxxx????x????xxxxxxxxxxx?xxxxxx";
#else
        static const char kGetRakServerPattern[] =
            "\x04\x24\xFF\xFF\xFF\xFF\x89\x75\xFF\x89\x5D\xFF\xE8\xFF\xFF\xFF\xFF\x89\x04\x24\x89"
            "\xC6\xE8\xFF\xFF\xFF\xFF\x89\xF0\x8B\x5D\xFF\x8B\x75\xFF\x89\xEC\x5D\xC3";
        static const char kGetRakServerMask[] =
            "xx????xx?xx?x????xxxxxx????xxxx?xx?xxxx";
#endif

        const auto [address, length] = GetModuleInfo(base);
        if (address == nullptr) return false;

        const auto pointer = Scanner(address, length).Find(kGetRakServerPattern, kGetRakServerMask);
        if (pointer == nullptr) return false;

        return _hook_getrakserver.Initialize(static_cast<adr_t>(pointer) - 7, GetRakServerHook);
    }

    void Deinitialize() noexcept
    {
        _hook_getrakserver.Deinitialize();

        _rakserver = nullptr;
    }

private:

    static Packet* THISCALL ReceiveHook(const ptr_t) noexcept
    {
        Packet* packet = Instance().Receive();

        if (Instance().OnPacket != nullptr)
        {
            while (packet != nullptr && Instance().OnPacket
                (packet->playerIndex, packet->data, packet->length))
            {
                Instance().DeallocatePacket(packet);
                packet = Instance().Receive();
            }
        }

        return packet;
    }

private:

    static ptr_t STDCALL GetRakServerHook() noexcept
    {
        const auto GetRakServer = Instance()._hook_getrakserver.Address();
        Instance()._hook_getrakserver.Deinitialize();

        Instance()._rakserver = reinterpret_cast<ptr_t(*)()>(GetRakServer)();
        if (Instance()._rakserver != nullptr)
        {
            const auto vtable = *static_cast<ptr_t**>(Instance()._rakserver);

            Instance()._receive = reinterpret_cast<raknet_receive_t>(vtable[kRaknetReceiveOffset]);
            Instance()._deallocatepacket = reinterpret_cast<raknet_deallocatepacket_t>(vtable[kRaknetDeallocatePacketOffset]);

            const UnprotectScope<sizeof(ptr_t)> scope { vtable + kRaknetReceiveOffset };
            vtable[kRaknetReceiveOffset] = ReceiveHook;
        }

        return Instance()._rakserver;
    }

private:

    Packet* Receive() noexcept
    {
        return _receive(_rakserver);
    }

    void DeallocatePacket(Packet* const packet) noexcept
    {
        _deallocatepacket(_rakserver, packet);
    }

public:

    std::function<bool(uword_t, cptr_t, uint_t)> OnPacket;

private:

    ptr_t _rakserver = nullptr;

    raknet_receive_t _receive = nullptr;
    raknet_deallocatepacket_t _deallocatepacket = nullptr;

    JumpHook _hook_getrakserver;

};
