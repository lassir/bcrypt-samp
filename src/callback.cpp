#include <set>

#include <boost/log/trivial.hpp>

#include "callback.h"
#include "plugin.h"

Callback::Callback()
{

}

Callback::Callback(std::string name)
{
	this->name = name;
}

Callback* Callback::setName(std::string name)
{
	this->name = name;
	return this;
}

Callback* Callback::addFromFormat(samp_sdk::AMX *amx, const char *format, samp_sdk::cell *params, unsigned int param_offset)
{
	using namespace samp_sdk;

	if (format == NULL)
		return this;

	cell *addr_ptr = NULL;
	unsigned int param_index = 1;

	do
	{
		char *str_buf = NULL;
		switch (*format)
		{
		case 'd':
		case 'i':
		case 'f':
			amx_GetAddr(amx, params[param_offset + param_index++], &addr_ptr);
			this->addParameter(*addr_ptr);
			break;

		case 's':
			amx_StrParam(amx, params[param_offset + param_index++], str_buf);
			this->addParameter(str_buf == NULL ? std::string() : std::string(str_buf));
			break;
		}
	} while (*(++format));

	return this;
}

Callback* Callback::addParameter(int parameter)
{
	this->parameters.push_front(parameter);
	return this;
}

Callback* Callback::addParameter(std::string parameter)
{
	this->parameters.push_front(parameter);
	return this;
}

Callback* Callback::exec()
{
	BOOST_LOG_TRIVIAL(trace) << "Executing callback " << this->getName() << "...";

	using namespace samp_sdk;

	if (this->name.empty())
		return this;

	std::set<AMX *> amx_list = Plugin::get()->getAmxList();

	for (std::set<AMX *>::iterator amx = amx_list.begin(); amx != amx_list.end(); ++amx)
	{
		BOOST_LOG_TRIVIAL(trace) << "  Callback::exec: " << *amx;
		int amx_idx = 0;

		if (amx_FindPublic(*amx, this->name.c_str(), &amx_idx) == AMX_ERR_NONE)
		{
			BOOST_LOG_TRIVIAL(trace) << "    => Public found.";

			cell amx_addr = -1;

			for (std::deque<boost::variant<int, std::string>>::iterator parameter = this->parameters.begin(); parameter != this->parameters.end(); ++parameter)
			{
				if (parameter->type() == typeid(int))
				{
					amx_Push((*amx), boost::get<int>(*parameter));
				}
				else
				{
					cell tmp_addr;
					amx_PushString((*amx), &tmp_addr, NULL, boost::get<std::string>(*parameter).c_str(), 0, 0);

					if (amx_addr < 0)
						amx_addr = tmp_addr;
				}
			}

			cell amx_ret;
			amx_Exec(*amx, &amx_ret, amx_idx);

			if (amx_addr >= 0)
				amx_Release(*amx, amx_addr);
		}
		else
		{
			BOOST_LOG_TRIVIAL(trace) << "    => Public not found.";
		}
	}
	return this;
}
