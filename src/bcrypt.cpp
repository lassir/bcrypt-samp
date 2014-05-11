#include <random>

#include "bcrypt.h"
#include "crypt_blowfish/ow-crypt.h"

#define CRYPT_OUTPUT_SIZE           (7 + 22 + 31 + 1)
#define CRYPT_GENSALT_OUTPUT_SIZE	(7 + 22 + 1)

bcrypt::bcrypt()
{
	this->cost = 12;
	this->prefix = "2y";
}

bcrypt* bcrypt::setCost(unsigned short cost)
{
	if(cost < 4)
	{
		this->cost = 4;
	}
	else if(cost > 31)
	{
		this->cost = 31;
	}
	else
	{
		this->cost = cost;
	}
	
	return this;
}

bcrypt* bcrypt::setPrefix(std::string prefix)
{
	if(prefix == "2a")
	{
		this->prefix = "$" + prefix + "$";
	}
	else
	{
		this->prefix = "$2y$";
	}
	
	return this;
}

bcrypt* bcrypt::setKey(std::string key)
{
	this->key = key;
		
	return this;
}

std::string bcrypt::generate()
{
	// Generate a random salt
	std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

	std::random_device RNG;
	std::uniform_int_distribution<int> index_distribution(0, charset.length() - 1);

	for (int i = 0; i < 22; ++i)
	{
		salt.push_back(charset.at(index_distribution(RNG)));
	}

	char settings[CRYPT_GENSALT_OUTPUT_SIZE];
	crypt_gensalt_rn(this->prefix.c_str(), this->cost, salt.c_str(), salt.length(), settings, CRYPT_GENSALT_OUTPUT_SIZE);

	// Use crypt_ra to ensure thread safety
	void *data = NULL;
	int size = 0x12345678;

	std::string hash;
	hash = crypt_ra(this->key.c_str(), settings, &data, &size);

	return hash;
}

bool bcrypt::compare(std::string key, std::string hash)
{
	// Validate hash length
	if (hash.length() != 60)
		return false;

	// Use crypt_ra to ensure thread safety
	void *data = NULL;
	int size = 0x12345678;

	char *compare = new char[CRYPT_OUTPUT_SIZE];
	compare = crypt_ra(key.c_str(), hash.c_str(), &data, &size);

	if (compare == hash)
		return true;
	else
		return false;
}
