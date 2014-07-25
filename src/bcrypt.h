#ifndef BCRYPT_H
#define BCRYPT_H

#include <string>

class Bcrypt
{
private:
	unsigned short cost;
	std::string prefix;
	std::string salt;
	std::string key;
	std::string hash;

public:
	Bcrypt();
	Bcrypt *setCost(unsigned short cost);
	Bcrypt *setPrefix(std::string prefix);
	Bcrypt *setKey(std::string key);
	Bcrypt *setHash(std::string hash);

	std::string getHash();
	
	void generate();
	bool compare();
};

#endif
