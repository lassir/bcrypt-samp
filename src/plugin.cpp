#include <thread>
#include <iostream>
#include <vector>
#include <cstdarg>

#include "plugin.h"
#include "bcrypt.h"

plugin *plugin::instance = NULL;

plugin::plugin()
{

}

plugin::~plugin()
{
	delete(this->instance);
	plugin::printf("plugin.bcrypt: Plugin unloaded.");
}

void plugin::initialise(void **ppData)
{
	instance = new plugin();

	instance->logprintf = (plugin::logprintf_t) ppData[samp_sdk::PLUGIN_DATA_LOGPRINTF];

	unsigned threads_supported = std::thread::hardware_concurrency();
	instance->thread_limit = threads_supported - 1;

	if (instance->thread_limit < 1)
		instance->thread_limit = 1;

	plugin::printf("  plugin.bcrypt " BCRYPT_VERSION " was loaded.");
	plugin::printf("  plugin.bcrypt: %d cores detected, %d threads will be used.", threads_supported, instance->thread_limit);
}

plugin *plugin::get()
{
	return instance;
}

void plugin::add_amx(samp_sdk::AMX *amx)
{
	this->amx_list.insert(amx);
}

void plugin::remove_amx(samp_sdk::AMX *amx)
{
	this->amx_list.erase(amx);
}

std::set<samp_sdk::AMX *> plugin::get_amx_list()
{
	return this->amx_list;
}

void plugin::printf(const char *format, ...)
{
	std::va_list arg_list;
	va_start(arg_list, format);

	char short_buf[256];
	vsnprintf(short_buf, sizeof(short_buf), format, arg_list);

    plugin::get()->logprintf((char *) short_buf);

	va_end(arg_list);
}

void plugin::set_thread_limit(unsigned value)
{
	this->thread_limit = value;
}

int plugin::get_thread_limit()
{
	return this->thread_limit;
}

void plugin::queue_task(unsigned short type, std::string key, unsigned short cost, callback *cb)
{
	this->task_queue.push({ type, key, cost, "", cb });
}

void plugin::queue_task(unsigned short type, std::string key, std::string hash, callback *cb)
{
	this->task_queue.push({ type, key, 0, hash, cb });
}

void plugin::queue_result(unsigned short type, std::string hash, bool match, callback *cb)
{
	std::lock_guard<std::mutex> lock(plugin::result_queue_mutex);

	this->result_queue.push({ type, hash, match, cb });
	this->active_threads--;
}

bool plugin::get_active_match()
{
	return plugin::get()->active_result.match;
}

std::string plugin::get_active_hash()
{
	return plugin::get()->active_result.hash;
}

void thread_generate_bcrypt(callback *cb, std::string buffer, short cost)
{
	bcrypt *crypter = new bcrypt();

	crypter
		->setCost(cost)
		->setPrefix("2y")
		->setKey(buffer);

	std::string hash = crypter->generate();

	delete(crypter);

	// Add the result to the queue
	plugin::get()->queue_result(E_QUEUE_HASH, hash, false, cb);
}

void thread_check_bcrypt(callback *cb, std::string password, std::string hash)
{
	bool match;
	match = bcrypt::compare(password, hash);

	// Add the result to the queue
	plugin::get()->queue_result(E_QUEUE_CHECK, std::string(), match, cb);
}

void plugin::process_task_queue()
{
	while (!this->task_queue.empty())
	{
		if (this->active_threads < this->thread_limit)
		{
			switch (this->task_queue.front().type)
			{
			case E_QUEUE_HASH:
			{
				// Start a new thread
				this->active_threads++;

				std::thread t(thread_generate_bcrypt, this->task_queue.front().cb, this->task_queue.front().key, this->task_queue.front().cost);
				t.detach();
				break;
			}
			case E_QUEUE_CHECK:
			{
				// Start a new thread
				this->active_threads++;

				std::thread t(thread_check_bcrypt, this->task_queue.front().cb, this->task_queue.front().key, this->task_queue.front().hash);
				t.detach();
				break;
			}

			default:
				break;
			}

			this->task_queue.pop();
		}
		else
		{
			break;
		}
	}
}

void plugin::process_result_queue()
{
	using namespace samp_sdk;

	std::lock_guard<std::mutex> lock(plugin::result_queue_mutex);

	while (!this->result_queue.empty())
	{
		this->active_result.hash = this->result_queue.front().hash;
		this->active_result.match = this->result_queue.front().match;
		
		this->result_queue.front().cb->exec();
		delete(this->result_queue.front().cb);

		this->result_queue.pop();
	}
}
