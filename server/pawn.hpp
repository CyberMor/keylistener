/*
    This is a KeyListener project file
    Developer: CyberMor <cyber.mor.2020@gmail.com>

    See more here https://github.com/CyberMor/keylistener

    Copyright (c) Daniel (CyberMor) 2020 All rights reserved
*/

#pragma once

#include <vector>

#include <types.hpp>

#include "pawn/amx/amx.h"
#include "pawn/plugincommon.h"

#include "raknet/networktypes.h"

struct AmxScript;

extern std::vector<AmxScript> gScripts;

struct AmxScript {

    AmxScript() = delete;
    ~AmxScript() noexcept = default;
    AmxScript(const AmxScript&) noexcept = default;
    AmxScript(AmxScript&&) noexcept = default;
    AmxScript& operator=(const AmxScript&) noexcept = default;
    AmxScript& operator=(AmxScript&&) noexcept = default;

public:

    AmxScript(AMX* const amx, const int onplayerkeydown, const int onplayerkeyup) noexcept
        : _amx             { amx }
        , _onplayerkeydown { onplayerkeydown }
        , _onplayerkeyup   { onplayerkeyup }
    {}

public:

    static bool Register(AMX* const amx) noexcept
    {
        int onplayerkeydown;
        int onplayerkeyup;

        if (amx_FindPublic(amx, "OnPlayerKeyDown", &onplayerkeydown) != 0 ||
            amx_FindPublic(amx, "OnPlayerKeyUp", &onplayerkeyup) != 0)
            return false;

        gScripts.emplace_back(amx, onplayerkeydown, onplayerkeyup);

        return true;
    }

public:

    void OnPlayerKeyDown(const uword_t player, const ubyte_t key) noexcept
    {
        amx_Push(_amx, static_cast<cell>(key));
        amx_Push(_amx, static_cast<cell>(player));
        amx_Exec(_amx, nullptr, _onplayerkeydown);
    }

    void OnPlayerKeyUp(const uword_t player, const ubyte_t key) noexcept
    {
        amx_Push(_amx, static_cast<cell>(key));
        amx_Push(_amx, static_cast<cell>(player));
        amx_Exec(_amx, nullptr, _onplayerkeyup);
    }

private:

    AMX* _amx;

private:

    int _onplayerkeydown;
    int _onplayerkeyup;

};

static std::vector<AmxScript> gScripts;

inline void OnPlayerKeyDown(const uword_t player, const ubyte_t key) noexcept
{
    for (auto& script : gScripts) script.OnPlayerKeyDown(player, key);
}

inline void OnPlayerKeyUp(const uword_t player, const ubyte_t key) noexcept
{
    for (auto& script : gScripts) script.OnPlayerKeyUp(player, key);
}
