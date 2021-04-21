// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.cpp.stl.PolymorphContainer -Wno-everything -verify %s

#include "Inputs/system-header-simulator-cxx.h"

struct X : std::vector<int> {};

int main()
{
  std::vector<int>* v = new X;// expected-warning {{Polymorphic use of an STL container is an error}}
  delete v;
}
