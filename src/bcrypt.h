#include <string>

class bcrypt
{
private:
	unsigned short cost;
	std::string prefix;
	std::string salt;
	std::string key;

public:
	bcrypt();
	bcrypt *setCost(unsigned short cost);
	bcrypt *setPrefix(std::string prefix);
	bcrypt *setKey(std::string key);
	
	std::string generate();
	static bool compare(std::string key, std::string hash);
};
