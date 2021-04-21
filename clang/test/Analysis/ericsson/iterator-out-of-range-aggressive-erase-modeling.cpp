// RUN: %clang_analyze_cc1 -std=c++11 \
// RUN: -analyzer-checker=core,cplusplus,alpha.ericsson.cpp.IteratorOutOfRange \
// RUN: -analyzer-config aggressive-binary-operation-simplification=true \
// RUN: -analyzer-config c++-container-inlining=false %s \
// RUN: -analyzer-config alpha.ericsson.cpp.IteratorOutOfRange:AggressiveEraseModeling=true \
// RUN: -analyzer-output=text -verify

// RUN: %clang_analyze_cc1 -std=c++11 \
// RUN: -analyzer-checker=core,cplusplus,alpha.ericsson.cpp.IteratorOutOfRange \
// RUN: -analyzer-config aggressive-binary-operation-simplification=true \
// RUN: -analyzer-config c++-container-inlining=true -DINLINE=1 %s \
// RUN: -analyzer-config alpha.ericsson.cpp.IteratorOutOfRange:AggressiveEraseModeling=true \
// RUN: -analyzer-output=text -verify

#include "Inputs/system-header-simulator-cxx.h"

extern void __assert_fail (__const char *__assertion, __const char *__file,
    unsigned int __line, __const char *__function)
     __attribute__ ((__noreturn__));
#define assert(expr) \
  ((expr)  ? (void)(0)  : __assert_fail (#expr, __FILE__, __LINE__, __func__))

void bad_erase_loop(std::list<int> L) {
  for (auto i = L.cbegin(); i != L.end(); ++i) { // expected-warning{{Iterator incremented behind the past-the-end iterator}}
                                                 // expected-note@-1{{Iterator incremented behind the past-the-end iterator}}
                                                 // expected-note@-2{{Assuming the container/range is non-empty}}
                                                 // expected-note@-3{{Loop condition is true}}
    i = L.erase(i);
  }
}

void bad_erase_loop(std::vector<int> V) {
  for (auto i = V.cbegin(); i != V.end(); ++i) { // expected-warning{{Iterator incremented behind the past-the-end iterator}}
                                                 // expected-note@-1{{Iterator incremented behind the past-the-end iterator}}
                                                 // expected-note@-2{{Assuming the container/range is non-empty}}
                                                 // expected-note@-3{{Loop condition is true}}
    i = V.erase(i);
  }
}
void bad_erase_loop(std::deque<int> D) {
  for (auto i = D.cbegin(); i != D.end(); ++i) { // expected-warning{{Iterator incremented behind the past-the-end iterator}}
                                                 // expected-note@-1{{Iterator incremented behind the past-the-end iterator}}
                                                 // expected-note@-2{{Assuming the container/range is non-empty}}
                                                 // expected-note@-3{{Loop condition is true}}
    i = D.erase(i);
  }
}
