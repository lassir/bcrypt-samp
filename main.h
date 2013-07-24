// -------------------------------------------------------------------------- // 
//
// bcrypt implementation for SA-MP
//
// Based on Botan crypto library (http://botan.randombit.net)
// License: BSD-2 (FreeBSD) http://botan.randombit.net/license.html
// 
// -------------------------------------------------------------------------- //

#include <thread>

#include "SDK/amx/amx.h"
#include "SDK/plugincommon.h"

#include "botan_all.h"

typedef void (*logprintf_t)(char* format, ...);
