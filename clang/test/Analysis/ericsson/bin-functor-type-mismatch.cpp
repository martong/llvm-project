// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.precpp11.stl.BinFunctorTypeMismatch -Wno-everything -verify %s

#include "Inputs/system-header-simulator-cxx.h"

typedef bool FakeBool;

struct Control
{
	bool operator()(int, long);
};

struct C : std::binary_function<int, long, char>
{
	char operator()(int, long);
};

struct C1 : std::binary_function<double, double, bool>
{
	bool operator()(int, double);// expected-warning {{The class 'C1' is an std::binary_function, but the types don't match on parameter 1: given type 'int' while expecting type 'double'}}
};

struct C2 : std::binary_function<int, char, bool>
{
	bool operator()(bool, char);// expected-warning {{The class 'C2' is an std::binary_function, but the types don't match on parameter 1: given type 'bool' while expecting type 'int'}}
};

struct C3 : std::binary_function<int, int, long>
{
	int operator()(int, int);// expected-warning {{The class 'C3' is an std::binary_function, but the types don't match on the return value: given type 'int' while expecting type 'long'}}
};

template <typename T>
struct TC
{
  T i;
};

typedef TC<int> TCInt;

struct CA : std::binary_function<int, TCInt, int>
{
	int operator()(int, const TC<int>&);
};

template<typename T>
struct CT : std::binary_function<T, int, bool>
{
	bool operator()(T, int);
};

template<typename T>
struct CT1 : std::binary_function<T, int, bool>
{
	bool operator()(double, int);// expected-warning {{The class 'CT1' is an std::binary_function, but the types don't match on parameter 1: given type 'double' while expecting template parameter 'T'}}
};

template<typename T>
struct CT2 : std::binary_function<T, int, T>
{
	bool operator()(T, int);// expected-warning {{The class 'CT2' is an std::binary_function, but the types don't match on the return value: given type 'bool' while expecting template parameter 'T'}}
};

template<typename T, typename U>
struct CT3 : std::binary_function<T, int, bool>
{
	bool operator()(U, int);// expected-warning {{The class 'CT3' is an std::binary_function, but the types don't match on parameter 1: given template parameter 'U' while expecting template parameter 'T'}}
};

template<typename T>
struct CTA : std::binary_function<T, int, FakeBool>
{
	bool operator()(T, int);// expected-warning {{The class 'CTA' is an std::binary_function, but the types don't match on the return value: given type 'bool' while expecting type 'FakeBool'}}
};

template<typename T>
struct CTA2 : std::binary_function<T, int, bool>
{
	bool operator()(T, const int&);
};

template<class T>
struct PairSecondSortReverse: public std::binary_function<
							  std::pair<T, double>,
							  std::pair<T, double>,
							  bool> {

	bool operator()(const std::pair<T, double> &LHS,
	                const std::pair<T, double> &RHS) const {
		return LHS.second > RHS.second;
	}
};

// TODO: false positive
template<typename T>
struct CTA3 : std::binary_function<T*, int, bool>
{
	bool operator()(const T*, const int&);
};
