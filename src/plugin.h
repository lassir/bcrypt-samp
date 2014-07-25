#ifndef PLUGIN_H
#define PLUGIN_H

#include <set>
#include <string>
#include <mutex>
#include <atomic>
#include <queue>

#include "main.h"
#include "callback.h"

extern void *pAMXFunctions;

class Plugin
{
private:
	typedef void (*logprintf_t)(char* format, ...);

	struct TaskQueue
	{
		unsigned short type;
		std::string key;
		unsigned short cost;
		std::string hash;
		Callback *cb;
	};

	struct ResultQueue
	{
		unsigned short type;
		std::string hash;
		bool match;
		Callback *cb;
	};

	static Plugin *instance;
	std::set<samp_sdk::AMX *> amx_list;
	
	logprintf_t logprintf;

	unsigned thread_limit;
	std::atomic<unsigned int> active_threads;

	std::queue<TaskQueue> task_queue;
	std::queue<ResultQueue> result_queue;
	std::mutex result_queue_mutex;

	struct
	{
		std::string hash;
		bool match;
	} active_result;

public:
	enum QueueType
	{
		HASH,
		CHECK
	};

	static void initialise(void **data);
	static Plugin *get();

	Plugin();
	~Plugin();

	static void printf(const char *format, ...);
	void addAmx(samp_sdk::AMX *amx);
	void removeAmx(samp_sdk::AMX *amx);
	std::set<samp_sdk::AMX *> getAmxList();

	void setThreadLimit(unsigned value);
	int getThreadLimit();

	void queueTask(unsigned short type, std::string key, unsigned short cost, Callback *cb);
	void queueTask(unsigned short type, std::string key, std::string hash, Callback *cb);
	void queueResult(unsigned short type, std::string hash, bool match, Callback *cb);

	void processTaskQueue();
	void processResultQueue();

	static bool getActiveMatch();
	static std::string getActiveHash();

	void generateBcryptThread(Callback *cb, std::string buffer, short cost);
	void checkBcryptThread(Callback *cb, std::string password, std::string hash);
};

#endif
