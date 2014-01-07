#include <thread>

#include "main.h"
#include "plugin.h"

using namespace samp_sdk;

extern void *pAMXFunctions;

// native bcrypt_hash(key[], cost, callback_name[], callback_format[], {Float, _}:...);
cell AMX_NATIVE_CALL bcrypt_hash(AMX* amx, cell* params)
{
	if (params[0] < 3 * sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: bcrypt_hash: Too few parameters (3 required)");
		return 0;
	}

	unsigned short cost = (unsigned short) params[2];

	if (cost < 4 || cost > 31)
	{
		plugin::printf("plugin.bcrypt: bcrypt_hash: Invalid work factor (expected 4-31)");
		return 0;
	}

	char
		*key = NULL,
		*callback_name = NULL,
		*callback_format = NULL;

	amx_StrParam(amx, params[1], key);
	amx_StrParam(amx, params[3], callback_name);
	amx_StrParam(amx, params[4], callback_format);

	if (key == NULL || callback_name == NULL)
		return 0;

	callback *cb = new callback();

	cb->setName(callback_name);
	cb->addFromFormat(amx, callback_format, params, 4);
	
	plugin::get()->queue_task(E_QUEUE_HASH, key, cost, cb);
	return 1;
}

// native bcrypt_check(thread_idx, thread_id, const password[], const hash[]);
cell AMX_NATIVE_CALL bcrypt_check(AMX* amx, cell* params)
{
	if (params[0] < 3 * sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: bcrypt_check: Too few parameters (3 required)");
		return 0;
	}

	char
		*key = NULL,
		*hash = NULL,
		*callback_name = NULL,
		*callback_format = NULL;

	amx_StrParam(amx, params[1], key);
	amx_StrParam(amx, params[2], hash);
	amx_StrParam(amx, params[3], callback_name);
	amx_StrParam(amx, params[4], callback_format);

	if (key == NULL || hash == NULL || callback_name == NULL)
		return 0;

	callback *cb = new callback();

	cb->setName(callback_name);
	cb->addFromFormat(amx, callback_format, params, 4);

	plugin::get()->queue_task(E_QUEUE_CHECK, key, hash, cb);
	return 1;
}

// native bcrypt_get_hash(destination[]);
cell AMX_NATIVE_CALL bcrypt_get_hash(AMX *amx, cell *params)
{
	if (params[0] != sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: bcrypt_get_hash: Invalid number of parameters (1 expected)");
		return 0;
	}

	cell *amx_dest_addr = NULL;
	amx_GetAddr(amx, params[1], &amx_dest_addr);
	amx_SetString(amx_dest_addr, plugin::get_active_hash().c_str(), 0, 0, 61);
	return 1;
}

// native bool:bcrypt_is_equal(destination[]);
cell AMX_NATIVE_CALL bcrypt_is_equal(AMX *amx, cell *params)
{
	return (int)plugin::get()->get_active_match();
}

// native bcrypt_set_thread_limit(value);
cell AMX_NATIVE_CALL bcrypt_set_thread_limit(AMX *amx, cell *params)
{
	if (params[0] != 1 * sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: The thread limit must be at least 1.");
		return 0;
	}

	unsigned thread_limit = (int) params[1];
	unsigned supported_threads = std::thread::hardware_concurrency();

	if (thread_limit >= 1)
	{
		plugin::get()->set_thread_limit(thread_limit);
	
		plugin::printf("plugin.bcrypt: Thread limit set to %d (CPU cores: %d)", thread_limit, supported_threads);
	}
	else
	{
		plugin::printf("plugin.bcrypt: The thread limit must be at least 1.");
		return 0;
	}

	return 1;
}

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION | SUPPORTS_PROCESS_TICK | SUPPORTS_AMX_NATIVES;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];

	plugin::initialise(ppData);
	return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	delete(plugin::get());
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	plugin::get()->process_result_queue();
	plugin::get()->process_task_queue();
}

AMX_NATIVE_INFO PluginNatives [] =
{
	{ "bcrypt_hash", bcrypt_hash },
	{ "bcrypt_check", bcrypt_check },
	{ "bcrypt_get_hash", bcrypt_get_hash },
	{ "bcrypt_is_equal", bcrypt_is_equal },
	{ "bcrypt_set_thread_limit", bcrypt_set_thread_limit },
	{ 0, 0 }
};

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
