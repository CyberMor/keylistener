/*
    This is a KeyListener project file
    Developer: CyberMor <cyber.mor.2020@gmail.com>

    See more here https://github.com/CyberMor/keylistener

    Copyright (c) Daniel (CyberMor) 2020 All rights reserved
*/

#include <version.hpp>

#include "pawn.hpp"
#include "network.hpp"

constexpr Version kCurrentVersion = MakeVersion(1, 1, 0);

constexpr ubyte_t kPacketKeyDown = 244;
constexpr ubyte_t kPacketKeyUp   = 245;

extern ptr_t pAMXFunctions;

static bool gKeys[1024][256] = {};

static bool OnPacket(const uword_t player, const cptr_t data, const uint_t size) noexcept
{
    if (size == 0) return false;

    const ubyte_t packet = static_cast<cadr_t>(data)[0];

    if (packet != kPacketKeyDown && packet != kPacketKeyUp)
        return false;

    if (size != 2) return false;

    const ubyte_t key = static_cast<cadr_t>(data)[1];

    switch (packet)
    {
        case kPacketKeyDown:
        {
            if (gKeys[player][key] == false)
            {
                OnPlayerKeyDown(player, key);
                gKeys[player][key] = true;
            }

            break;
        }
        case kPacketKeyUp:
        {
            if (gKeys[player][key] == true)
            {
                OnPlayerKeyUp(player, key);
                gKeys[player][key] = false;
            }

            break;
        }
    }

    return true;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void* const* const ppData) noexcept
{
    pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];

    const auto logprintf = reinterpret_cast<void(*)(cstr_t,...)>(ppData[PLUGIN_DATA_LOGPRINTF]);

    Network::Instance().OnPacket = OnPacket;

    if (!Network::Instance().Initialize(ppData[PLUGIN_DATA_LOGPRINTF]))
    {
        logprintf("[KeyListener] : failed to initialize network module");
        return false;
    }

    logprintf("KeyListener v%hhu.%hhu.%hu by MOR loaded",
        GetVersionMajor(kCurrentVersion),
        GetVersionMinor(kCurrentVersion),
        GetVersionPatch(kCurrentVersion));

    return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload() noexcept
{}

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX* const amx) noexcept
{
    AmxScript::Register(amx);

    return AMX_ERR_NONE;
}

PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX* const) noexcept
{
    return AMX_ERR_NONE;
}

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports() noexcept
{
    return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES;
}
