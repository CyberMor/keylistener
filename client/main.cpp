/*
    This is a KeyListener project file
    Developer: CyberMor <cyber.mor.2020@gmail.com>

    See more here https://github.com/CyberMor/keylistener

    Copyright (c) Daniel (CyberMor) 2020 All rights reserved
*/

#include <Windows.h>

#include <version.hpp>

#include "network.hpp"

constexpr Version kCurrentVersion = MakeVersion(1, 1, 0);

constexpr ubyte_t kPacketKeyDown = 244;
constexpr ubyte_t kPacketKeyUp   = 245;

static bool gKeys[256] = {};

static LONG gOriginalWindowProcedure = NULL;

static LRESULT WINAPI WindowProcedure(const HWND window, const UINT message,
    const WPARAM wparam, const UINT lparam) noexcept
{
    switch (message)
    {
        case WM_KEYDOWN:
        {
            if (gKeys[wparam] == false)
            {
                ubyte_t buffer[2];

                buffer[0] = kPacketKeyDown;
                buffer[1] = static_cast<ubyte_t>(wparam);

                Network::Instance().SendPacket(buffer, sizeof(buffer));

                gKeys[wparam] = true;
            }

            break;
        }
        case WM_KEYUP:
        {
            if (gKeys[wparam] == true)
            {
                ubyte_t buffer[2];

                buffer[0] = kPacketKeyUp;
                buffer[1] = static_cast<ubyte_t>(wparam);

                Network::Instance().SendPacket(buffer, sizeof(buffer));

                gKeys[wparam] = false;
            }

            break;
        }
        case WM_CLOSE:
        {
            break;
        }
    }

    return CallWindowProc(reinterpret_cast<WNDPROC>(gOriginalWindowProcedure),
        window, message, wparam, lparam);
}

static DWORD WINAPI WaitingThread(const LPVOID) noexcept
{
    while (*reinterpret_cast<const volatile HWND*>(0xC97C1C) == NULL)
        Sleep(100);

    gOriginalWindowProcedure = SetWindowLong(*reinterpret_cast<const volatile HWND*>(0xC97C1C),
        GWL_WNDPROC, reinterpret_cast<LONG>(WindowProcedure));

    return EXIT_SUCCESS;
}

BOOL APIENTRY DllMain(const HMODULE, const DWORD reason, const LPVOID) noexcept
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        if (!Network::Instance().Initialize(LoadLibrary("samp.dll")))
            return FALSE;

        if (CreateThread(NULL, 0, WaitingThread, NULL, 0, NULL) == NULL)
            return FALSE;
    }

    return TRUE;
}
