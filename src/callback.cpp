#include <set>

#include "callback.h"
#include "plugin.h"

callback::callback()
{

}

void callback::setName(std::string name)
{
	this->name = name;
}

void callback::addFromFormat(samp_sdk::AMX *amx, const char *format, samp_sdk::cell *params, unsigned int param_offset)
{
	using namespace samp_sdk;

	if (format == NULL)
		return;

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
}

void callback::addParameter(int parameter)
{
	this->parameters.push_front(parameter);
}

void callback::addParameter(std::string parameter)
{
	this->parameters.push_front(parameter);
}

void callback::exec()
{
	using namespace samp_sdk;

	if (this->name.empty())
		return;

	std::set<AMX *> amx_list = plugin::get()->get_amx_list();

	for (std::set<AMX *>::iterator amx = amx_list.begin(); amx != amx_list.end(); ++amx)
	{
		int amx_idx = 0;

		if (amx_FindPublic((*amx), this->name.c_str(), &amx_idx) == AMX_ERR_NONE)
		{
			cell amx_addr = -1;

			for (std::deque<boost::variant<int, std::string>>::iterator parameter = this->parameters.begin(); parameter != this->parameters.end(); ++parameter)
			{
				const boost::variant<int, std::string> &param = (*parameter);

				if (param.type() == typeid(int))
				{
					amx_Push((*amx), boost::get<int>(param));
				}
				else
				{
					cell tmp_addr;
					amx_PushString((*amx), &tmp_addr, NULL, boost::get<std::string>(param).c_str(), 0, 0);

					if (amx_addr < 0)
						amx_addr = tmp_addr;
				}
			}

			cell amx_ret;
			amx_Exec((*amx), &amx_ret, amx_idx);

			if (amx_addr >= 0)
				amx_Release((*amx), amx_addr);
		}
	}
}
