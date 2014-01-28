#ifndef NATIVES_H
#define NATIVES_H

#include "main.h"

#define DECLARE_NATIVE(function) \
	cell AMX_NATIVE_CALL function(AMX *amx, cell *params)

#define DEFINE_NATIVE(function) \
	{ #function, native::function },

namespace native 
{
	using namespace samp_sdk;

	DECLARE_NATIVE(bcrypt_hash);
	DECLARE_NATIVE(bcrypt_get_hash);
	DECLARE_NATIVE(bcrypt_check);
	DECLARE_NATIVE(bcrypt_is_equal);
	DECLARE_NATIVE(bcrypt_set_thread_limit);
}

#endif
