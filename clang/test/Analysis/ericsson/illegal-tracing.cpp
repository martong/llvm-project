// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.mtas.IllegalTracing -Wno-everything -verify %s

#include "Inputs/system-header-simulator.h"
#include "Inputs/system-header-simulator-cxx.h"
#include "Inputs/system-header-simulator-cxx-iostream.h"

void illegal_c_tracing() {
    printf("foobar");// expected-warning {{It is prohibited to use cstdio for tracing in MTAS code}}
}

void illegal_candcpp_tracing() {
    std::printf("foobar");// expected-warning {{It is prohibited to use cstdio for tracing in MTAS code}}
}

void illegal_cpp_tracing() {
    std::cout << "foobar" << std::endl;// expected-warning {{It is prohibited to use iostreams for tracing in MTAS code}}
}

void illegal_cpp_tracing_cerr() {
    std::cerr << "foobar" << std::endl;// expected-warning {{It is prohibited to use iostreams for tracing in MTAS code}}
}

void illegal_cpp_tracing_with_using() {
    using namespace std;
    cout << "foobar" << endl;// expected-warning {{It is prohibited to use iostreams for tracing in MTAS code}}
}

void should_not_crash_with_fn_ptrs() {
	void (*p)() = &illegal_cpp_tracing_with_using;
	p();
}
