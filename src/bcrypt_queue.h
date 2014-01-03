enum BCRYPT_QUEUE_TYPE
{
	BCRYPT_QUEUE_HASH,
	BCRYPT_QUEUE_CHECK
};

struct bcrypt_queue_item
{
	unsigned short type;
	int thread_idx;
	int thread_id;
	std::string hash;
	bool match;
};

std::vector<bcrypt_queue_item> bcrypt_queue;
