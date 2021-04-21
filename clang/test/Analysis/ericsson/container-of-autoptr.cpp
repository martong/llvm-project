// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.cpp.stl.ContainerOfAutoptr -Wno-everything -verify %s

#include "Inputs/system-header-simulator-cxx.h"

template<typename T> class wrapper {};

typedef std::auto_ptr<char> CharPtr;

int main()
{
	std::vector<std::auto_ptr<int>> v;// expected-warning {{Using containers of std::auto_ptrs is not recommended, because standard algorithms involving assignments (e.g. std::sort) will invalidate them}}
	std::vector<CharPtr> v2;// expected-warning {{Using containers of std::auto_ptrs is not recommended, because standard algorithms involving assignments (e.g. std::sort) will invalidate them}}
	wrapper<std::set<std::auto_ptr<int>>> w;// expected-warning {{Using containers of std::auto_ptrs is not recommended, because standard algorithms involving assignments (e.g. std::sort) will invalidate them}}
	std::set<std::auto_ptr<int>> s;// expected-warning {{Using containers of std::auto_ptrs is not recommended, because standard algorithms involving assignments (e.g. std::sort) will invalidate them}}
	// control
	std::vector<int> c1;
	std::set<int> c2;
	std::vector<wrapper<CharPtr>> c3;

	std::auto_ptr<int> p;

	return 0;
}
