// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.mtas.EpctParameters -Wno-everything -verify %s

#include "Inputs/system-header-simulator.h"
#include "Inputs/system-header-simulator-cxx.h"
#include "Inputs/system-header-simulator-cxx-string.h"

class DicosEnvironment
{
public:
    enum status {
    	success = 0,
    	unset_key = 1,
    	parse_error = 2,
    	range_error = 3,
    	db_error = 100,
    };

    static status get(std::string& value,
		      const std::string& key,
		      ssize_t waitTime = -1);

    static int get(const char key[],
		   char* buffer,
		   unsigned int bufferLength,
		   int waitTime = -1);


    static unsigned int getUnsignedInt(const char* key,
				       unsigned int defaultValue,
				       int waitTime = -1);

    static void set(const char key[], const char value[], bool* isOk = 0);
    static void unset(const char key[],  bool* isOk = 0);
    DicosEnvironment();
    ~DicosEnvironment();
    bool getFirst(std::string& key, std::string& value);
    bool getNext(std::string& key, std::string& value);
    bool iterationOk();

    enum Constants {
	PortName = 1002520
    };

private:
    class DicosEnvironmentRep* rep;
};

int foo() {
    char * buf = new char[32];
    DicosEnvironment::get("foo", buf, 32);// expected-warning {{Using epct parameters for configuration should be deprecated}}
    delete buf;
}

int bar() {
    DicosEnvironment env;
    std::string a, b;
    env.getFirst(a, b);// expected-warning {{Using epct parameters for configuration should be deprecated}}
}
