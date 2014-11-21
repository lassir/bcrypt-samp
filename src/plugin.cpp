#include <thread>
#include <iostream>
#include <vector>
#include <cstdarg>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

#include "main.h"
#include "plugin.h"
#include "bcrypt.h"

namespace expr = boost::log::expressions;
namespace keywords = boost::log::keywords;

Plugin *Plugin::instance = NULL;

Plugin::Plugin()
{

}

Plugin::~Plugin()
{
	Plugin::printf("plugin.bcrypt: Plugin unloaded.");
	BOOST_LOG_TRIVIAL(info) << "Plugin unloaded.";
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

	boost::log::add_file_log(
		keywords::file_name = "bcrypt_log.txt",
		keywords::auto_flush = true,
		keywords::format = expr::stream
			<< expr::format_date_time< boost::posix_time::ptime >("TimeStamp", "%Y-%m-%d %H:%M:%S") 
			<< " <" << boost::log::trivial::severity << "> "
			<< expr::message
	);

	boost::log::core::get()->set_filter(
		boost::log::trivial::severity >= boost::log::trivial::trace
	);

	boost::log::add_common_attributes();

	Plugin::printf("  plugin.bcrypt " BCRYPT_VERSION " was loaded.");
	Plugin::printf("  plugin.bcrypt: %d cores detected, %d threads will be used.", threads_supported, instance->thread_limit);

	BOOST_LOG_TRIVIAL(info) << "Plugin version " << BCRYPT_VERSION << " loaded.";
}

Plugin *Plugin::get()
{
	return instance;
}

void Plugin::addAmx(samp_sdk::AMX *amx)
{
	BOOST_LOG_TRIVIAL(trace) << "Registered AMX: " << amx;
	this->amx_list.insert(amx);
}

void Plugin::removeAmx(samp_sdk::AMX *amx)
{
	BOOST_LOG_TRIVIAL(trace) << "Unregistered AMX: " << amx;
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
	BOOST_LOG_TRIVIAL(debug) << "Thread limit set to " << value;
	this->thread_limit = value;
}

int Plugin::getThreadLimit()
{
	return this->thread_limit;
}

void Plugin::queueTask(unsigned short type, std::string key, unsigned short cost, Callback *cb)
{
	BOOST_LOG_TRIVIAL(debug) << "Task queued: '" << cb->getName() << "'";
	this->task_queue.push({ type, key, cost, "", cb });
}

void Plugin::queueTask(unsigned short type, std::string key, std::string hash, Callback *cb)
{
	BOOST_LOG_TRIVIAL(debug) << "Task queued: '" << cb->getName() << "'";
	this->task_queue.push({ type, key, 0, hash, cb });
}

void Plugin::queueResult(unsigned short type, std::string hash, bool match, Callback *cb)
{
	BOOST_LOG_TRIVIAL(trace) << "Queue result: '" << cb->getName() << "'. Waiting for mutex.";
	std::lock_guard<std::mutex> lock(Plugin::result_queue_mutex);

	BOOST_LOG_TRIVIAL(debug) << "Queue result: '" << cb->getName() << "'. Mutex obtained, adding to queue.";
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
	BOOST_LOG_TRIVIAL(debug) << "Thread created: generateBcryptThread (" << cb->getName() << ")";

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
	BOOST_LOG_TRIVIAL(debug) << "Thread created: checkBcryptThread (" << cb->getName() << ")";

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
					BOOST_LOG_TRIVIAL(trace) << "Preparing to create a thread for '" << this->task_queue.front().cb->getName() << "'";
					this->active_threads++;

					std::thread t(&Plugin::generateBcryptThread, this, this->task_queue.front().cb, this->task_queue.front().key, this->task_queue.front().cost);
					t.detach();
					break;
				}
				case QueueType::CHECK:
				{
					// Start a new thread
					BOOST_LOG_TRIVIAL(trace) << "Preparing to create a thread for '" << this->task_queue.front().cb->getName() << "'";
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
		BOOST_LOG_TRIVIAL(debug) << "Calling callback '" << this->result_queue.front().cb->getName() << "'";

		this->active_result.hash = this->result_queue.front().hash;
		this->active_result.match = this->result_queue.front().match;
		
		this->result_queue.front().cb->exec();
		delete(this->result_queue.front().cb);

		this->result_queue.pop();
	}
}
