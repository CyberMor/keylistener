/*
    This is a KeyListener project file
    Developer: CyberMor <cyber.mor.2020@gmail.com>

    See more here https://github.com/CyberMor/keylistener

    Copyright (c) Daniel (CyberMor) 2020 All rights reserved
*/

#pragma once

#include <cassert>

#include "types.hpp"
#include "patch.hpp"

struct JumpHook {

    JumpHook() noexcept = default;
    ~JumpHook() noexcept = default;
    JumpHook(const JumpHook&) = delete;
    JumpHook(JumpHook&&) noexcept = default;
    JumpHook& operator=(const JumpHook&) = delete;
    JumpHook& operator=(JumpHook&&) noexcept = default;

private:

#pragma pack(push, 1)

    struct JumpInstruction {

        JumpInstruction() = delete;
        ~JumpInstruction() noexcept = default;
        JumpInstruction(const JumpInstruction&) noexcept = default;
        JumpInstruction(JumpInstruction&&) noexcept = default;
        JumpInstruction& operator=(const JumpInstruction&) noexcept = default;
        JumpInstruction& operator=(JumpInstruction&&) noexcept = default;

    public:

        JumpInstruction(const sdword_t offset) noexcept
            : offset { offset }
        {}

    public:

         ubyte_t opcode = 0xE9;
        sdword_t offset;

    };

#pragma pack(pop)

public:

    JumpHook(const ptr_t inject, const cptr_t hook, const bool enabled = true) noexcept
        : _patch { inject, &JumpInstruction((sdword_t)(hook) - ((sdword_t)(inject) +
            (sdword_t)(sizeof(JumpInstruction)))), enabled }
    {
        assert(hook != nullptr);
    }

public:

    bool Valid() const noexcept
    {
        return _patch.Valid();
    }

    bool Invalid() const noexcept
    {
        return _patch.Invalid();
    }

public:

    bool Initialize(const ptr_t inject, const cptr_t hook, const bool enabled = true) noexcept
    {
        assert(hook != nullptr);

        return _patch.Initialize(inject, &JumpInstruction((sdword_t)(hook) -
            ((sdword_t)(inject) + (sdword_t)(sizeof(JumpInstruction)))), enabled);
    }

    void Deinitialize() noexcept
    {
        _patch.Deinitialize();
    }

public:

    void Enable() noexcept
    {
        _patch.Enable();
    }

    void Disable() noexcept
    {
        _patch.Disable();
    }

public:

    ptr_t Address() const noexcept
    {
        return _patch.Address();
    }

    constexpr size_t Length() const noexcept
    {
        return _patch.Length();
    }

private:

    Patch<sizeof(JumpInstruction)> _patch;

};
