#ifndef PLUGIN_H
#define PLUGIN_H

#include <set>
#include <string>
#include <mutex>
#include <atomic>
#include <queue>

#include "main.h"
#include "callback.h"

enum E_QUEUE_TYPE
{
	E_QUEUE_HASH,
	E_QUEUE_CHECK
};

struct s_task_queue
{
	unsigned short type;
	std::string key;
	unsigned short cost;
	std::string hash;
	callback *callback;
};

struct s_result_queue
{
	unsigned short type;
	std::string hash;
	bool match;
	callback *callback;
};

class plugin
{
	typedef void (*logprintf_t)(char* format, ...);
	
private:
	static plugin *instance;
	std::set<samp_sdk::AMX *> amx_list;
	
	logprintf_t logprintf;

	unsigned thread_limit;
	std::atomic<unsigned> active_threads;

	std::queue<s_task_queue> task_queue;
	std::queue<s_result_queue> result_queue;
	std::mutex result_queue_mutex;

	struct
	{
		std::string hash;
		bool match;
	} active_result;

public:
	static void initialise(void **ppData);
	static plugin *get();

	plugin();
	~plugin();

	static void printf(const char *format, ...);
	void add_amx(samp_sdk::AMX *amx);
	void remove_amx(samp_sdk::AMX *amx);
	std::set<samp_sdk::AMX *> get_amx_list();

	void set_thread_limit(unsigned value);
	int get_thread_limit();

	void queue_task(unsigned short type, std::string key, unsigned short cost, callback *callback);
	void queue_task(unsigned short type, std::string key, std::string hash, callback *callback);
	void queue_result(unsigned short type, std::string hash, bool match, callback *callback);

	void process_task_queue();
	void process_result_queue();

	static bool get_active_match();
	static std::string get_active_hash();
};

#endif
