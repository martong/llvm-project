// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.precpp11.stl.UnaryFunctorTypeMismatch -Wno-everything -verify %s

#include "Inputs/system-header-simulator-cxx.h"

typedef bool FakeBool;

struct Control
{
  bool operator()(int);
};

struct C : std::unary_function<int, long>
{
  char operator()(int);// expected-warning {{The class 'C' is an std::unary_function, but the types don't match on the return value: given type 'char' while expecting type 'long'}}
};

struct C1 : std::unary_function<double, double>
{
  bool operator()(int);// expected-warning {{The class 'C1' is an std::unary_function, but the types don't match on the parameter: given type 'int' while expecting type 'double'}}
};

struct C2 : std::unary_function<int, bool>
{
  bool operator()(bool);// expected-warning {{The class 'C2' is an std::unary_function, but the types don't match on the parameter: given type 'bool' while expecting type 'int'}}
};

struct C3 : std::unary_function<int, int>
{
  int operator()(int);
};

template<typename T>
struct CT : std::unary_function<T, bool>
{
  bool operator()(T);
};

template<typename T>
struct CT1 : std::unary_function<T, int>
{
  bool operator()(double);// expected-warning {{The class 'CT1' is an std::unary_function, but the types don't match on the parameter: given type 'double' while expecting template parameter 'T'}}
};

template<typename T>
struct CT2 : std::unary_function<T, int>
{
  bool operator()(T);// expected-warning {{The class 'CT2' is an std::unary_function, but the types don't match on the return value: given type 'bool' while expecting type 'int'}}
};

template<typename T, typename U>
struct CT3 : std::unary_function<T, int>
{
  bool operator()(U);// expected-warning {{The class 'CT3' is an std::unary_function, but the types don't match on the parameter: given template parameter 'U' while expecting template parameter 'T'}}
};

template<typename T>
struct CTA : std::unary_function<T, FakeBool>
{
  bool operator()(T);// expected-warning {{The class 'CTA' is an std::unary_function, but the types don't match on the return value: given type 'bool' while expecting type 'FakeBool'}}
};

template<typename T>
struct CTA2 : std::unary_function<T, bool>
{
  bool operator()(const T&);
};
