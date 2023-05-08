/*
    This is a KeyListener project file
    Developer: CyberMor <cyber.mor.2020@gmail.com>

    See more here https://github.com/CyberMor/keylistener

    Copyright (c) Daniel (CyberMor) 2020 All rights reserved
*/

#pragma once

#include <cassert>

#include "types.hpp"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#endif

template <size_t Size>
struct UnprotectScope {

    static_assert(Size > 0);

public:

    UnprotectScope() noexcept = default;
    ~UnprotectScope() noexcept
    {
        Disable();
    }

    UnprotectScope(const UnprotectScope&) = delete;
    UnprotectScope(UnprotectScope&& object) noexcept
        : _address { object._address }
        , _enabled { object._enabled }
#ifdef _WIN32
        , _protect { object._protect }
#endif
    {
        object._address = nullptr;
        object._enabled = false;
    }

    UnprotectScope& operator=(const UnprotectScope&) = delete;
    UnprotectScope& operator=(UnprotectScope&& object) noexcept
    {
        if (&object != this)
        {
            Disable();

            _address = object._address;
            _enabled = object._enabled;
#ifdef _WIN32
            _protect = object._protect;
#endif

            object._address = nullptr;
            object._enabled = false;
        }

        return *this;
    }

public:

    UnprotectScope(const ptr_t address, const bool enabled = true) noexcept
        : _address { address }
    {
        if (enabled) Enable();
    }

public:

    bool Valid() const noexcept
    {
        return _address != nullptr;
    }

    bool Invalid() const noexcept
    {
        return _address == nullptr;
    }

public:

    bool Initialize(const ptr_t address, const bool enabled = true) noexcept
    {
        Disable();

        _address = address;
#ifdef _WIN32
        _protect = PAGE_EXECUTE_READWRITE;
#endif

        if (enabled) Enable();

        return _address != nullptr &&
            (enabled == false || _enabled == true);
    }

    void Deinitialize() noexcept
    {
        Disable();

        _address = nullptr;
    }

public:

    void Enable() noexcept
    {
        if (_enabled == false)
        {
            assert(_address != nullptr);
#ifdef _WIN32
            assert(_protect == PAGE_EXECUTE_READWRITE);

            if (VirtualProtect(_address, Size, _protect, &_protect) != 0)
                _enabled = true;
#else
            if (const long page_size = sysconf(_SC_PAGESIZE); page_size != -1)
            {
                const size_t begin = (size_t)(_address) & ~((size_t)(page_size) - 1);
                const size_t end   = (size_t)(_address) + Size;

                if (mprotect((ptr_t)(begin), end - begin, PROT_READ | PROT_WRITE | PROT_EXEC) == 0)
                    _enabled = true;
            }
#endif
        }
    }

    void Disable() noexcept
    {
        if (_enabled == true)
        {
            assert(_address != nullptr);
#ifdef _WIN32
            if (VirtualProtect(_address, Size, _protect, &_protect) != 0)
                _enabled = false;
#endif
        }
    }

public:

    ptr_t Address() const noexcept
    {
        return _address;
    }

    constexpr size_t Length() const noexcept
    {
        return Size;
    }

private:

    ptr_t _address = nullptr;
    bool  _enabled = false;
#ifdef _WIN32
    DWORD _protect = PAGE_EXECUTE_READWRITE;
#endif

};

inline bool UnprotectMemory(const ptr_t address, const size_t length) noexcept
{
#ifdef _WIN32
    if (DWORD protect; VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &protect) != 0)
        return true;
#else
    if (const long page_size = sysconf(_SC_PAGESIZE); page_size != -1)
    {
        const size_t begin = (size_t)(address) & ~((size_t)(page_size) - 1);
        const size_t end   = (size_t)(address) + length;

        if (mprotect((ptr_t)(begin), end - begin, PROT_READ | PROT_WRITE | PROT_EXEC) == 0)
            return true;
    }
#endif
    return false;
}
