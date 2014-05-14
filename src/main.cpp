#include "plugin.h"
#include "natives.h"

using namespace samp_sdk;

AMX_NATIVE_INFO PluginNatives [] =
{
	DEFINE_NATIVE(bcrypt_hash)
	DEFINE_NATIVE(bcrypt_check)
	DEFINE_NATIVE(bcrypt_get_hash)
	DEFINE_NATIVE(bcrypt_is_equal)
	DEFINE_NATIVE(bcrypt_set_thread_limit)
	{ 0, 0 }
};

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	plugin::initialise(ppData);
	return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	delete(plugin::get());
}

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx)
{
	plugin::get()->add_amx(amx);
	return amx_Register(amx, PluginNatives, -1);
}

PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx)
{
	plugin::get()->remove_amx(amx);
	return AMX_ERR_NONE;
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	plugin::get()->process_result_queue();
	plugin::get()->process_task_queue();
}

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION | SUPPORTS_PROCESS_TICK | SUPPORTS_AMX_NATIVES;
}
