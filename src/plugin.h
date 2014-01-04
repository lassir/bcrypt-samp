#include <vector>
#include <set>
#include <string>
#include <mutex>

#include "main.h"

enum E_QUEUE_TYPE
{
	E_QUEUE_HASH,
	E_QUEUE_CHECK
};

struct s_task_queue
{
	unsigned short type;
	int thread_idx;
	int thread_id;
};

struct s_result_queue
{
	unsigned short type;
	int thread_idx;
	int thread_id;
	std::string hash;
	bool match;
};

class plugin
{

private:
	static plugin *instance;
	std::set<samp_sdk::AMX *> amx_list;

	int use_threads;

	std::vector<s_task_queue> task_queue;
	std::vector<s_result_queue> result_queue;
	std::mutex result_queue_mutex;

	void *pAMXFunctions;

public:
	static void initialise(void **ppData);
	static plugin *get();
	logprintf_t logprintf;

	plugin();
	~plugin();
	
	void plugin::add_amx(samp_sdk::AMX *amx);
	void plugin::remove_amx(samp_sdk::AMX *amx);

	void queue_task(unsigned short type, int thread_idx, int thread_id);
	void queue_result(unsigned short type, int thread_idx, int thread_id, std::string hash, bool match);

	void process_result_queue();
};