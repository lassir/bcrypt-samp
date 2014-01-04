#include <thread>

#include "plugin.h"

plugin *plugin::instance = NULL;

plugin::plugin()
{

}

plugin::~plugin()
{
	this->logprintf("plugin.bcrypt: Plugin unloaded.");
}

void plugin::initialise(void **ppData)
{
	instance = new plugin();

	instance->logprintf = (logprintf_t) ppData[samp_sdk::PLUGIN_DATA_LOGPRINTF];

	unsigned max_threads = std::thread::hardware_concurrency();
	unsigned use_threads = max_threads - 1;

	if (use_threads < 1)
		use_threads = 1;

	instance->logprintf("  plugin.bcrypt "BCRYPT_VERSION" was loaded.");
	instance->logprintf("  plugin.bcrypt: %d cores found, %d concurrent threads will be used.", max_threads, use_threads);
}

plugin *plugin::get()
{
	return instance;
}

void plugin::add_amx(samp_sdk::AMX *amx)
{
	get()->amx_list.insert(amx);
}

void plugin::remove_amx(samp_sdk::AMX *amx)
{
	get()->amx_list.erase(amx);
}

void plugin::queue_task(unsigned short type, int thread_idx, int thread_id)
{
	this->task_queue.push_back({ type, thread_idx, thread_id });
}

void plugin::queue_result(unsigned short type, int thread_idx, int thread_id, std::string hash, bool match)
{
	std::lock_guard<std::mutex> lock(plugin::result_queue_mutex);

	this->result_queue.push_back({ type, thread_idx, thread_id, hash, match });
}

void plugin::process_result_queue()
{
	using namespace samp_sdk;

	if (this->result_queue.size() > 0)
	{
		std::lock_guard<std::mutex> lock(plugin::result_queue_mutex);

		int amx_idx;
		for (std::set<AMX *>::iterator a = this->amx_list.begin(); a != this->amx_list.end(); ++a)
		{
			for (std::vector<s_result_queue>::iterator t = this->result_queue.begin(); t != this->result_queue.end(); ++t)
			{
				if ((*t).type == E_QUEUE_HASH)
				{
					// public OnBcryptHashed(thread_idx, thread_id, const hash[]);

					if (!amx_FindPublic(*a, "OnBcryptHashed", &amx_idx))
					{
						// Push the hash
						cell addr;
						amx_PushString(*a, &addr, NULL, (*t).hash.c_str(), NULL, NULL);

						// Push the thread_id and thread_idx
						amx_Push(*a, (*t).thread_id);
						amx_Push(*a, (*t).thread_idx);

						// Execute and release memory
						amx_Exec(*a, NULL, amx_idx);
						amx_Release(*a, addr);
					}
				}
				else if ((*t).type == E_QUEUE_CHECK)
				{
					// public OnBcryptChecked(thread_idx, thread_id, bool:match);

					if (!amx_FindPublic(*a, "OnBcryptChecked", &amx_idx))
					{
						// Push the thread_id and thread_idx
						amx_Push(*a, (*t).match);
						amx_Push(*a, (*t).thread_id);
						amx_Push(*a, (*t).thread_idx);

						// Execute and release memory
						amx_Exec(*a, NULL, amx_idx);
					}
				}
			}
		}

		// Clear the queue
		this->result_queue.clear();
	}
}