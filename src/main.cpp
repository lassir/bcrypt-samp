#include "plugin.h"
#include "natives.h"

using namespace samp_sdk;

AMX_NATIVE_INFO PluginNatives [] =
{
	DEFINE_NATIVE(bcrypt_hash)
	DEFINE_NATIVE(bcrypt_check)
	DEFINE_NATIVE(bcrypt_get_hash)
	DEFINE_NATIVE(bcrypt_is_equal)
	DEFINE_NATIVE(bcrypt_needs_rehash)
	DEFINE_NATIVE(bcrypt_find_cost)
	DEFINE_NATIVE(bcrypt_set_thread_limit)
	{ 0, 0 }
};

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **data)
{
	Plugin::initialise(data);
	return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	delete(Plugin::get());
}

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx)
{
	Plugin::get()->addAmx(amx);
	return amx_Register(amx, PluginNatives, -1);
}

PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx)
{
	Plugin::get()->removeAmx(amx);
	return AMX_ERR_NONE;
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	Plugin::get()->processResultQueue();
	Plugin::get()->processTaskQueue();
}

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION | SUPPORTS_PROCESS_TICK | SUPPORTS_AMX_NATIVES;
}
