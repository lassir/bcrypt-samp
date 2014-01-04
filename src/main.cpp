#include <thread>
#include <vector>
#include <mutex>

#include "main.h"
#include "plugin.h"
#include "bcrypt.h"

using namespace samp_sdk;

extern void *pAMXFunctions;

// native bcrypt_hash(thread_idx, thread_id, password[], cost);
cell AMX_NATIVE_CALL bcrypt_hash(AMX* amx, cell* params)
{
	// Require 4 parameters
	if (params[0] != 4 * sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: bcrypt_hash: Invalid number of parameters (expected 4)");
		return 0;
	}

	// Get the parameters
	int thread_idx = (int) params[1];
	int thread_id = (int) params[2];
	unsigned short cost = (unsigned short) params[4];

	if (cost < 4 || cost > 31)
	{
		plugin::printf("plugin.bcrypt: bcrypt_hash: Invalid work factor (expected 4-31)");
		return 0;
	}

	std::string password = "";

	int len = 0;
	cell *addr = NULL;

	amx_GetAddr(amx, params[3], &addr);
	amx_StrLen(addr, &len);

	if (len++)
	{
		char *buffer = new char[len];
		amx_GetString(buffer, addr, 0, len);

		password = std::string(buffer);

		delete [] buffer;
	}

	plugin::get()->queue_task(E_QUEUE_HASH, thread_idx, thread_id, password, cost);
	return 1;
}

// native bcrypt_check(thread_idx, thread_id, const password[], const hash[]);
cell AMX_NATIVE_CALL bcrypt_check(AMX* amx, cell* params)
{
	// Require 4 parameters
	if (params[0] != 4 * sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: bcrypt_check: Invalid number of parameters (expected 4)");
		return 0;
	}

	// Get the parameters
	int thread_idx = (int) params[1];
	int thread_id = (int) params[2];

	std::string password = "";
	std::string hash = "";

	int len[2] = { 0, 0 };
	cell *addr[2] = { NULL, NULL };

	amx_GetAddr(amx, params[3], &addr[0]);
	amx_StrLen(addr[0], &len[0]);

	amx_GetAddr(amx, params[4], &addr[1]);
	amx_StrLen(addr[1], &len[1]);

	if (len[0]++)
	{
		char *buffer = new char[len[0]];
		amx_GetString(buffer, addr[0], 0, len[0]);

		password = std::string(buffer);

		delete [] buffer;
	}

	if (len[1]++)
	{
		char *buffer = new char[len[1]];
		amx_GetString(buffer, addr[1], 0, len[1]);

		hash = std::string(buffer);

		delete [] buffer;
	}

	plugin::get()->queue_task(E_QUEUE_CHECK, thread_idx, thread_id, password, hash);
	return 1;
}

cell AMX_NATIVE_CALL bcrypt_set_thread_limit(AMX *amx, cell *params)
{
	if (params[0] != 1 * sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: The thread limit must be at least 1.");
		return 0;
	}

	int thread_limit = (int) params[1];
	int supported_threads = std::thread::hardware_concurrency();

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
