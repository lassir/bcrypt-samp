OUTFILE = bcrypt-samp.so

GPP = g++ -m32
COMPILER_FLAGS = -c -O3 --std=c++11 -D _strdup=strdup
LINKER_FLAGS = -O2 -fshort-wchar -shared -lpthread

CRYPT_OBJECTS = crypt_blowfish.o crypt_gensalt.o wrapper.o
OBJECTS = amxplugin.o $(CRYPT_OBJECTS) bcrypt.o plugin.o callback.o natives.o main.o

bcrypt:
	$(GPP) $(COMPILER_FLAGS) -U__i386__ src/crypt_blowfish/*.cpp
	$(GPP) $(COMPILER_FLAGS) src/SDK/*.cpp
	$(GPP) $(COMPILER_FLAGS) src/*.cpp
	$(GPP) $(LINKER_FLAGS) -o $(OUTFILE) $(OBJECTS)

