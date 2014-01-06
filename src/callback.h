#ifndef CALLBACK_H
#define CALLBACK_H

#include <string>
#include <deque>
#include <boost/variant.hpp>

#include "main.h"

class callback
{

public:
	callback();
	~callback();

	void setName(std::string name);
	void addFromFormat(samp_sdk::AMX *amx, const char *format, samp_sdk::cell *params, unsigned int param_offset);
	void addParameter(int parameter);
	void addParameter(std::string parameter);

	void exec();

private:
	std::set<samp_sdk::AMX *> amx_list;
	std::string name;
	std::deque< boost::variant<int, std::string> > parameters;
};

#endif