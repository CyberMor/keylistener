#include <pawn/amx/amx.h>
#include <pawn/plugincommon.h>

#include <raknet/bitstream.h>
#include <raknet/networktypes.h>

typedef void(*logprintf_t)(const char* format, ...);
logprintf_t logprintf;

extern void *pAMXFunctions;
void **ppPluginData;

#include "main.h"

#include "mem.hpp"
#include "pwn.h"
#include "net.h"

PLUGIN_EXPORT bool PLUGIN_CALL Load(
	void **ppData
) {
	
	ppPluginData = ppData;
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	logprintf = (logprintf_t)(ppData[PLUGIN_DATA_LOGPRINTF]);

	if (!net::init(ppData[PLUGIN_DATA_LOGPRINTF])) {
		logprintf("[KeyListener] : could not initialize net module");
		return false;
	}

	logprintf("KeyListener plugin v" KL_VERSION_TEXT " by MOR loaded");
	return true;

}
PLUGIN_EXPORT void PLUGIN_CALL Unload() {}
PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx) {
	pawn::script::reg(amx);
	return AMX_ERR_NONE;
}
PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx) {
	return AMX_ERR_NONE;
}
PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports() {
	return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES;
}
