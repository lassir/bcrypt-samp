#include <thread>
#include <vector>
#include <mutex>

#include "main.h"
#include "plugin.h"
#include "bcrypt.h"

using namespace samp_sdk;

extern void *pAMXFunctions;

void bcrypt_error(std::string funcname, std::string error)
{
	plugin::get()->logprintf("bcrypt error: %s (Called from %s)", error.c_str(), funcname.c_str());
}

void thread_generate_bcrypt(int thread_idx, int thread_id, std::string buffer, short cost)
{
	bcrypt *crypter = new bcrypt();

	crypter
		->setCost(cost)
		->setPrefix("2y")
		->setKey(buffer);

	std::string hash = crypter->generate();

	delete(crypter);

	// Add the result to the queue
	plugin::get()->queue_result(E_QUEUE_HASH, thread_idx, thread_id, hash, false);
}

// native bcrypt_hash(thread_idx, thread_id, password[], cost);
cell AMX_NATIVE_CALL bcrypt_hash(AMX* amx, cell* params)
{
	// Require 4 parameters
	if (params[0] != 4 * sizeof(cell))
	{
		bcrypt_error("bcrypt_hash", "Incorrect number of parameters (4 required)");
		return 0;
	}

	// Get the parameters
	int thread_idx = (int) params[1];
	int thread_id = (int) params[2];
	unsigned short cost = (unsigned short) params[4];

	if (cost < 4 || cost > 31)
	{
		bcrypt_error("bcrypt_hash", "Invalid work factor (cost). Allowed range: 4-31");
		return 0;
	}

	std::string password = "";

	int len = NULL;
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

	// Start a new thread
	std::thread t(thread_generate_bcrypt, thread_idx, thread_id, password, cost);

	// Leave the thread running
	t.detach();
	return 1;
}

void thread_check_bcrypt(int thread_idx, int thread_id, std::string password, std::string hash)
{
	bool match;
	match = bcrypt::compare(password, hash);

	// Add the result to the queue
	plugin::get()->queue_result(E_QUEUE_CHECK, thread_idx, thread_id, "", match);
}

// native bcrypt_check(thread_idx, thread_id, const password[], const hash[]);
cell AMX_NATIVE_CALL bcrypt_check(AMX* amx, cell* params)
{
	// Require 4 parameters
	if (params[0] != 4 * sizeof(cell))
	{
		bcrypt_error("bcrypt_check", "Incorrect number of parameters (4 required)");
		return 0;
	}

	// Get the parameters
	int thread_idx = (int) params[1];
	int thread_id = (int) params[2];

	std::string password = "";
	std::string hash = "";

	int len[2] = { NULL };
	cell *addr[2] = { NULL };

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

	// Start a new thread
	std::thread t(thread_check_bcrypt, thread_idx, thread_id, password, hash);

	// Leave the thread running
	t.detach();
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
}

AMX_NATIVE_INFO PluginNatives [] =
{
	{"bcrypt_hash", bcrypt_hash},
	{"bcrypt_check", bcrypt_check },
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
