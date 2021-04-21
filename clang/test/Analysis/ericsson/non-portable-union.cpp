// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.NonPortableUnion -Wno-everything -verify %s
#include "Inputs/system-header-simulator.h"

void execute_memsize_union() {
  union PtrNumUnion_wrong { // expected-warning {{This union may be prone to 32 to 64 bits portability problems}}
    char *m_p; // expected-note {{memsize or pointer field}}
    int m_n; // expected-note {{32-bit wide field}}
  } w;

  union PtrNumUnion_right { //correct
    char *m_pt;
    intptr_t m_n;
  } r;

  union PtrNumUnion_wrong2 { // expected-warning {{This union may be prone to 32 to 64 bits portability problems}}
    char *m_p; // expected-note {{memsize or pointer field}}
    struct {
      unsigned char b0, b1, b2, b3;
    } bytes; // expected-note {{32-bit wide field}}
  } w2;

  union PtrNumUnion_right2 { // correct
    char *m_p;
    struct {
      unsigned char bytes[sizeof(m_p)];
    } bytes;
  } r2;

  union SizetToBytesUnion_wrong { // expected-warning {{This union may be prone to 32 to 64 bits portability problems}}
    size_t value; // expected-note {{memsize or pointer field}}
    struct {
      unsigned char b0, b1, b2, b3; 
    } bytes; // expected-note {{32-bit wide field}}
  } uw;

  union SizetToBytesUnion_right { //correct
    size_t value;
    unsigned char bytes[sizeof(value)];
  } uc;

  union SizetToBytesUnion_no_report { //the union has more than 2 fields, which indicates it may not be
                                      //used for type conversion.
    size_t value;
    int i;
    struct { 
      unsigned char b0, b1, b2, b3; 
    } bytes;
  } u_noreport;
}

