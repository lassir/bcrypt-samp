// -------------------------------------------------------------------------- //
//
// bcrypt implementation for SA-MP
//
// Based on Botan crypto library (http://botan.randombit.net)
// License: BSD-2 (FreeBSD) http://botan.randombit.net/license.html
//
// -------------------------------------------------------------------------- //

#include "main.h"
#include <iostream>

Botan::LibraryInitializer init;

logprintf_t logprintf;
extern void *pAMXFunctions;

void bcrypt_error(std::string funcname, std::string error)
{
	logprintf("bcrypt error: %s (Called from %s)", error.c_str(), funcname.c_str());
}

void thread_generate_bcrypt(AMX* amx, int playerid, int threadid, std::string buffer, short cost)
{
	Botan::AutoSeeded_RNG rng;

	std::string output_str = Botan::generate_bcrypt(buffer, rng, cost);

	int idx;
	if(!amx_FindPublic(amx, "OnBcryptHashed", &idx))
	{
		// public OnBcryptHashed(playerid, thread, const hash[]);

		// Push the hash
		cell addr;
		amx_PushString(amx, &addr, NULL, output_str.c_str(), NULL, NULL);

		// Push the threadid and playerid
		amx_Push(amx, threadid);
		amx_Push(amx, playerid);

		// Execute and release memory
		amx_Exec(amx, NULL, idx);
		amx_Release(amx, addr);
	}
}

// native bcrypt_hash(playerid, thread, password[], cost);
cell AMX_NATIVE_CALL bcrypt_hash(AMX* amx, cell* params)
{
	// Require 4 parameters
	if(params[0] != 4 * sizeof(cell))
	{
		bcrypt_error("bcrypt_hash", "Incorrect number of parameters (4 required)");
		return 0;
	}

	// Get the parameters
	unsigned short playerid = (unsigned short) params[1];
	int threadid = (int) params[2];
	unsigned short cost = (unsigned short) params[4];

	if(cost < 4 || cost > 31)
	{
		bcrypt_error("bcrypt_hash", "Invalid work factor (cost). Allowed range: 4-31");
		return 0;
	}

	std::string password = "";

	int len = NULL;
	cell *addr = NULL;

	amx_GetAddr(amx, params[3], &addr);
	amx_StrLen(addr, &len);

	if(len++)
	{
		char *buffer = new char[len];
		amx_GetString(buffer, addr, 0, len);

		password = std::string(buffer);

		delete[] buffer;
	}

	// Start a new thread
	std::thread t(thread_generate_bcrypt, amx, playerid, threadid, password, cost);

	// Leave the thread running
	t.detach();
	return 1;
}

void thread_check_bcrypt(AMX* amx, int playerid, int threadid, std::string password, std::string hash)
{
	bool match;

	// Hash cannot be valid if it's not 60 characters long
	if(hash.length() != 60)
		match = false;
	else
	{
		match = Botan::check_bcrypt(password, hash);
	}

	int idx;
	if(!amx_FindPublic(amx, "OnBcryptChecked", &idx))
	{
		// public OnBcryptChecked(playerid, thread, bool:match);

		// Push the threadid and playerid
		amx_Push(amx, match);
		amx_Push(amx, threadid);
		amx_Push(amx, playerid);

		// Execute and release memory
		amx_Exec(amx, NULL, idx);
	}
}

// native bcrypt_check(playerid, thread, const password[], const hash[]);
cell AMX_NATIVE_CALL bcrypt_check(AMX* amx, cell* params)
{
	// Require 4 parameters
	if(params[0] != 4 * sizeof(cell))
	{
		bcrypt_error("bcrypt_check", "Incorrect number of parameters (4 required)");
		return 0;
	}

	// Get the parameters
	unsigned short playerid = (unsigned short) params[1];
	int threadid = (int) params[2];

	std::string password = "";
	std::string hash = "";

	int len[2] = {NULL};
	cell *addr[2] = {NULL};

	amx_GetAddr(amx, params[3], &addr[0]);
	amx_StrLen(addr[0], &len[0]);

	amx_GetAddr(amx, params[4], &addr[1]);
	amx_StrLen(addr[1], &len[1]);

	if(len[0]++)
	{
		char *buffer = new char[len[0]];
		amx_GetString(buffer, addr[0], 0, len[0]);

		password = std::string(buffer);

		delete[] buffer;
	}

	if(len[1]++)
	{
		char *buffer = new char[len[1]];
		amx_GetString(buffer, addr[1], 0, len[1]);

		hash = std::string(buffer);

		delete[] buffer;
	}

	// Start a new thread
	std::thread t(thread_check_bcrypt, amx, playerid, threadid, password, hash);

	// Leave the thread running
	t.detach();
	return 1;
}

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	logprintf = (logprintf_t) ppData[PLUGIN_DATA_LOGPRINTF];

	logprintf("");
	logprintf(" ======================================== ");
	logprintf("");
	logprintf("  bcrypt for SA-MP was loaded");
	logprintf("");
	logprintf(" ======================================== ");
	logprintf("");
	return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	logprintf("");
	logprintf(" ======================================== ");
	logprintf("");
	logprintf("  bcrypt for SA-MP was unloaded");
	logprintf("");
	logprintf(" ======================================== ");
	logprintf("");
}

AMX_NATIVE_INFO PluginNatives[] =
{
	{"bcrypt_hash", bcrypt_hash},
	{"bcrypt_check", bcrypt_check},
	{0, 0}
};

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad( AMX *amx )
{
	return amx_Register(amx, PluginNatives, -1);
}


PLUGIN_EXPORT int PLUGIN_CALL AmxUnload( AMX *amx )
{
	return AMX_ERR_NONE;
}
