# This file demonstrates how to compile the bcrypt project on Linux.
#
# To compile do:
#
# make bcrypt
#

GPP = g++
GCC = gcc
OUTFILE = "./bcrypt.so"

COMPILE_FLAGS = -c -O3 -w -D LINUX -I ./SDK/amx/ --std=c++11 -fPIC -m32 -pthread

clean:
	-rm *~ *.o *.so

bcrypt: clean
	$(GCC) $(COMPILE_FLAGS) ./SDK/amx/*.c
	$(GPP) $(COMPILE_FLAGS) ./SDK/*.cpp
	$(GPP) $(COMPILE_FLAGS) ./*.cpp
	$(GPP) -O2 -fshort-wchar -shared -ldl -lrt -o $(OUTFILE) *.o

# You may use bcrypt_quick if you do not need to compile the Botan library
bcrypt_quick:
	$(GPP) $(COMPILE_FLAGS) ./main.cpp
	$(GPP) -O2 -fshort-wchar -shared -ldl -lrt -o $(OUTFILE) *.o
