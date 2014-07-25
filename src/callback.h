#ifndef CALLBACK_H
#define CALLBACK_H

#include <string>
#include <deque>
#include <boost/variant.hpp>

#include "main.h"

class Callback
{

public:
	Callback();
	Callback(std::string name);

	Callback* setName(std::string name);
	Callback* addFromFormat(samp_sdk::AMX *amx, const char *format, samp_sdk::cell *params, unsigned int param_offset);
	Callback* addParameter(int parameter);
	Callback* addParameter(std::string parameter);

	Callback* exec();

private:
	std::set<samp_sdk::AMX *> amx_list;
	std::string name;
	std::deque< boost::variant<int, std::string> > parameters;
};

#endif