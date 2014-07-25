#include <thread>
#include <cstring>

#include "plugin.h"
#include "natives.h"

using namespace samp_sdk;

// native bcrypt_hash(key[], cost, callback_name[], callback_format[], {Float, _}:...);
DECLARE_NATIVE(native::bcrypt_hash)
{
	if (params[0] < 3 * sizeof(cell))
	{
		Plugin::printf("plugin.bcrypt: bcrypt_hash: Too few parameters (3 required)");
		return 0;
	}

	unsigned short cost = static_cast<unsigned short>(params[2]);

	if (cost < 4 || cost > 31)
	{
		Plugin::printf("plugin.bcrypt: bcrypt_hash: Invalid work factor (expected 4-31)");
		return 0;
	}

	char
		*key = NULL,
		*callback_name = NULL,
		*callback_format = NULL;

	amx_StrParam(amx, params[1], key);
	amx_StrParam(amx, params[3], callback_name);
	amx_StrParam(amx, params[4], callback_format);

	if (callback_name == NULL)
		return 0;

	Callback *cb = new Callback(callback_name);
	cb->addFromFormat(amx, callback_format, params, 4);

	Plugin::get()->queueTask(Plugin::QueueType::HASH, (key != NULL ? key : std::string()), cost, cb);
	return 1;
}

// native bcrypt_check(thread_idx, thread_id, const password[], const hash[]);
DECLARE_NATIVE(native::bcrypt_check)
{
	if (params[0] < 3 * sizeof(cell))
	{
		Plugin::printf("plugin.bcrypt: bcrypt_check: Too few parameters (3 required)");
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

	if (callback_name == NULL)
		return 0;

	Callback *cb = new Callback(callback_name);
	cb->addFromFormat(amx, callback_format, params, 4);

	Plugin::get()->queueTask(Plugin::QueueType::CHECK, (key != NULL ? key : std::string()), (hash != NULL ? hash : std::string()), cb);
	return 1;
}

// native bcrypt_get_hash(destination[]);
DECLARE_NATIVE(native::bcrypt_get_hash)
{
	if (params[0] != sizeof(cell))
	{
		Plugin::printf("plugin.bcrypt: bcrypt_get_hash: Invalid number of parameters (1 expected)");
		return 0;
	}

	cell *amx_dest_addr = NULL;
	amx_GetAddr(amx, params[1], &amx_dest_addr);
	amx_SetString(amx_dest_addr, Plugin::getActiveHash().c_str(), 0, 0, 61);
	return 1;
}

// native bool:bcrypt_is_equal(destination[]);
DECLARE_NATIVE(native::bcrypt_is_equal)
{
	return Plugin::get()->getActiveMatch();
}

// native bool:bcrypt_needs_rehash(hash[], cost);
DECLARE_NATIVE(native::bcrypt_needs_rehash)
{
	if (params[0] != sizeof(cell) * 2)
	{
		Plugin::printf("plugin.bcrypt: bcrypt_needs_rehash: Invalid number of parameters (2 expected)");
	}

	char *hash = NULL;
	unsigned expected_cost;

	amx_StrParam(amx, params[1], hash);
	expected_cost = static_cast<unsigned>(params[2]);

	if (hash[0] != '$' || hash[1] != '2' || hash[2] != 'y' || hash[3] != '$' || hash[6] != '$' || strlen(hash) != 60)
		return 1;

	unsigned cost = (hash[4] - '0') * 10 + (hash[5] - '0');
	if (cost != expected_cost)
		return 1;

	return 0;
}

// native bcrypt_set_thread_limit(value);
DECLARE_NATIVE(native::bcrypt_set_thread_limit)
{
	if (params[0] != 1 * sizeof(cell))
	{
		Plugin::printf("plugin.bcrypt: The thread limit must be at least 1.");
		return 0;
	}

	unsigned thread_limit = static_cast<int>(params[1]);
	unsigned supported_threads = std::thread::hardware_concurrency();

	if (thread_limit >= 1)
	{
		Plugin::get()->setThreadLimit(thread_limit);

		Plugin::printf("plugin.bcrypt: Thread limit set to %d (CPU cores: %d)", thread_limit, supported_threads);
	}
	else
	{
		Plugin::printf("plugin.bcrypt: The thread limit must be at least 1.");
		return 0;
	}

	return 1;
}
