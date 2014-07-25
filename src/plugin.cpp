#include <thread>
#include <iostream>
#include <vector>
#include <cstdarg>

#include "main.h"
#include "plugin.h"
#include "bcrypt.h"

Plugin *Plugin::instance = NULL;

Plugin::Plugin()
{

}

Plugin::~Plugin()
{
	Plugin::printf("plugin.bcrypt: Plugin unloaded.");
}

void Plugin::initialise(void **data)
{
	pAMXFunctions = data[samp_sdk::PLUGIN_DATA_AMX_EXPORTS];

	instance = new Plugin();
	instance->logprintf = (Plugin::logprintf_t) data[samp_sdk::PLUGIN_DATA_LOGPRINTF];

	unsigned threads_supported = std::thread::hardware_concurrency();
	instance->thread_limit = threads_supported - 1;

	if (instance->thread_limit < 1)
		instance->thread_limit = 1;

	Plugin::printf("  plugin.bcrypt " BCRYPT_VERSION " was loaded.");
	Plugin::printf("  plugin.bcrypt: %d cores detected, %d threads will be used.", threads_supported, instance->thread_limit);
}

Plugin *Plugin::get()
{
	return instance;
}

void Plugin::addAmx(samp_sdk::AMX *amx)
{
	this->amx_list.insert(amx);
}

void Plugin::removeAmx(samp_sdk::AMX *amx)
{
	this->amx_list.erase(amx);
}

std::set<samp_sdk::AMX *> Plugin::getAmxList()
{
	return this->amx_list;
}

void Plugin::printf(const char *format, ...)
{
	std::va_list arg_list;
	va_start(arg_list, format);

	char short_buf[256];
	vsnprintf(short_buf, sizeof(short_buf), format, arg_list);

	Plugin::get()->logprintf((char *)short_buf);

	va_end(arg_list);
}

void Plugin::setThreadLimit(unsigned value)
{
	this->thread_limit = value;
}

int Plugin::getThreadLimit()
{
	return this->thread_limit;
}

void Plugin::queueTask(unsigned short type, std::string key, unsigned short cost, Callback *cb)
{
	this->task_queue.push({ type, key, cost, "", cb });
}

void Plugin::queueTask(unsigned short type, std::string key, std::string hash, Callback *cb)
{
	this->task_queue.push({ type, key, 0, hash, cb });
}

void Plugin::queueResult(unsigned short type, std::string hash, bool match, Callback *cb)
{
	std::lock_guard<std::mutex> lock(Plugin::result_queue_mutex);

	this->result_queue.push({ type, hash, match, cb });
	this->active_threads--;
}

bool Plugin::getActiveMatch()
{
	return instance->active_result.match;
}

std::string Plugin::getActiveHash()
{
	return instance->active_result.hash;
}

void Plugin::generateBcryptThread(Callback *cb, std::string buffer, short cost)
{
	Bcrypt *crypter = new Bcrypt();

	crypter
		->setCost(cost)
		->setPrefix("2y")
		->setKey(buffer)
		->generate();

	// Add the result to the queue
	this->queueResult(QueueType::HASH, crypter->getHash(), false, cb);
	
	delete crypter;
}

void Plugin::checkBcryptThread(Callback *cb, std::string password, std::string hash)
{
	Bcrypt *crypter = new Bcrypt();

	crypter
		->setKey(password)
		->setHash(hash);

	bool match = crypter->compare();

	// Add the result to the queue
	this->queueResult(QueueType::CHECK, std::string(), match, cb);
}

void Plugin::processTaskQueue()
{
	while (!this->task_queue.empty())
	{
		if (this->active_threads < this->thread_limit)
		{
			switch (this->task_queue.front().type)
			{
				case QueueType::HASH:
				{
					// Start a new thread
					this->active_threads++;

					std::thread t(&Plugin::generateBcryptThread, this, this->task_queue.front().cb, this->task_queue.front().key, this->task_queue.front().cost);
					t.detach();
					break;
				}
				case QueueType::CHECK:
				{
					// Start a new thread
					this->active_threads++;

					std::thread t(&Plugin::checkBcryptThread, this, this->task_queue.front().cb, this->task_queue.front().key, this->task_queue.front().hash);
					t.detach();
					break;
				}
			}

			this->task_queue.pop();
		}
		else
		{
			break;
		}
	}
}

void Plugin::processResultQueue()
{
	using namespace samp_sdk;

	std::lock_guard<std::mutex> lock(Plugin::result_queue_mutex);

	while (!this->result_queue.empty())
	{
		this->active_result.hash = this->result_queue.front().hash;
		this->active_result.match = this->result_queue.front().match;
		
		this->result_queue.front().cb->exec();
		delete(this->result_queue.front().cb);

		this->result_queue.pop();
	}
}
