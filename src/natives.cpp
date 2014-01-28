#include <thread>

#include "natives.h"
#include "plugin.h"

using namespace native;

// native bcrypt_hash(key[], cost, callback_name[], callback_format[], {Float, _}:...);
DECLARE_NATIVE(native::bcrypt_hash)
{
	if (params[0] < 3 * sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: bcrypt_hash: Too few parameters (3 required)");
		return 0;
	}

	unsigned short cost = (unsigned short)params[2];

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
DECLARE_NATIVE(native::bcrypt_check)
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
DECLARE_NATIVE(native::bcrypt_get_hash)
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
DECLARE_NATIVE(native::bcrypt_is_equal)
{
	return (int)plugin::get()->get_active_match();
}

// native bcrypt_set_thread_limit(value);
DECLARE_NATIVE(native::bcrypt_set_thread_limit)
{
	if (params[0] != 1 * sizeof(cell))
	{
		plugin::printf("plugin.bcrypt: The thread limit must be at least 1.");
		return 0;
	}

	unsigned thread_limit = (int)params[1];
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
