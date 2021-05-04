// RUN: %clang_analyze_cc1 -triple x86_64 -analyzer-checker=core,alpha.ericsson.SufficientSizeArrayIndexing %s -verify

#include "Inputs/system-header-simulator.h"

#define one_byte_signed_max ((1ULL << 7) - 1)
#define two_byte_signed_max ((1ULL << 15) - 1)
#define four_byte_signed_max ((1ULL << 31) - 1)

#define one_byte_unsigned_max ((1ULL << 8) - 1)
#define two_byte_unsigned_max ((1ULL << 16) - 1)
#define four_byte_unsigned_max ((1ULL << 32) - 1)


char smaller_than_1byte_signed_range[one_byte_signed_max];
char exactly_1byte_signed_range[one_byte_signed_max + 1];
char greater_than_1byte_signed_range[one_byte_signed_max + 2];

char smaller_than_2byte_signed_range[two_byte_signed_max];
char exactly_2byte_signed_range[two_byte_signed_max + 1];
char greater_than_2byte_signed_range[two_byte_signed_max + 2];

char smaller_than_4byte_signed_range[four_byte_signed_max];
char exactly_4byte_signed_range[four_byte_signed_max + 1];
char greater_than_4byte_signed_range[four_byte_signed_max + 2];


char smaller_than_1byte_unsigned_range[one_byte_unsigned_max];
char exactly_1byte_unsigned_range[one_byte_unsigned_max + 1];
char greater_than_1byte_unsigned_range[one_byte_unsigned_max + 2];

char smaller_than_2byte_unsigned_range[two_byte_unsigned_max];
char exactly_2byte_unsigned_range[two_byte_unsigned_max + 1];
char greater_than_2byte_unsigned_range[two_byte_unsigned_max + 2];

char smaller_than_4byte_unsigned_range[four_byte_unsigned_max];
char exactly_4byte_unsigned_range[four_byte_unsigned_max + 1];
char greater_than_4byte_unsigned_range[four_byte_unsigned_max + 2];


const char one_byte_signed_index = 1; // sizeof(char) == 1
const short two_byte_signed_index = 1; // sizeof(short) == 2
const int four_byte_signed_index = 1; // sizeof(int) == 4

const unsigned char one_byte_unsigned_index = 1;
const unsigned short two_byte_unsigned_index = 1;
const unsigned int four_byte_unsigned_index = 1;

void ignore_literal_indexing() {
  char a = exactly_4byte_unsigned_range[32]; // nowarning
}

void ignore_literal_indexing_with_parens() {
  char a = exactly_4byte_unsigned_range[(32)]; // nowarning
}

void range_check_one_byte_index() {
  char r;
  char* pr = &r;
  *pr = smaller_than_1byte_signed_range[one_byte_signed_index]; // nowarning
  *pr = exactly_1byte_signed_range[one_byte_signed_index]; // nowarning
  *pr = greater_than_1byte_signed_range[one_byte_signed_index]; // expected-warning{{Indexing array with type 'char' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}

  *pr = smaller_than_1byte_unsigned_range[one_byte_unsigned_index]; // nowarning
  *pr = exactly_1byte_unsigned_range[one_byte_unsigned_index]; // nowarning
  *pr = greater_than_1byte_unsigned_range[one_byte_unsigned_index]; // expected-warning{{Indexing array with type 'unsigned char' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}
}


void range_check_two_byte_index() {
  char r;
  char* pr = &r;
  *pr = smaller_than_2byte_signed_range[two_byte_signed_index]; // nowarning
  *pr = exactly_2byte_signed_range[two_byte_signed_index]; // nowarning
  *pr = greater_than_2byte_signed_range[two_byte_signed_index]; // expected-warning{{Indexing array with type 'short' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}

  *pr = smaller_than_2byte_unsigned_range[two_byte_unsigned_index]; // nowarning
  *pr = exactly_2byte_unsigned_range[two_byte_unsigned_index]; // nowarning
  *pr = greater_than_2byte_unsigned_range[two_byte_unsigned_index]; // expected-warning{{Indexing array with type 'unsigned short' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}
}

void range_check_four_byte_index() {
  char r;
  char* pr = &r;
  *pr = smaller_than_4byte_signed_range[four_byte_signed_index]; // nowarning
  *pr = exactly_4byte_signed_range[four_byte_signed_index]; // nowarning
  *pr = greater_than_4byte_signed_range[four_byte_signed_index]; // expected-warning{{Indexing array with type 'int' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}

  *pr = smaller_than_4byte_unsigned_range[four_byte_unsigned_index]; // nowarning
  *pr = exactly_4byte_unsigned_range[four_byte_unsigned_index]; // nowarning
  *pr = greater_than_4byte_unsigned_range[four_byte_unsigned_index]; // expected-warning{{Indexing array with type 'unsigned int' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}
}

char* f(int choice) {
  switch (choice) {
    case 0:
      return smaller_than_4byte_signed_range;
    case 1:
      return exactly_4byte_signed_range;
    case 2:
      return greater_than_4byte_signed_range;
    default:
      return  NULL;
  }
}

void test_symbolic_index_handling() {
  char c;
  c = (f(0)[four_byte_signed_index]); // nowarning
  c = (f(1)[four_byte_signed_index]); // nowarning
  c = (f(2)[four_byte_signed_index]); // expected-warning{{Indexing array with type 'int' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}
}

void test_symbolic_index_handling2(int choice) {
  char c;
  if (choice < 2) {
    if (choice >= 1) {
      c = f(choice)[four_byte_signed_index]; // nowarnining // the value is one or two, f returns an array that is correct in size
    }
  }
}

void test_symbolic_index_handling3(int choice) {
  char c;
  if (choice < 3) {
    if (choice > 1) {
      c = f(choice)[four_byte_signed_index]; // expected-warning{{Indexing array with type 'int' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}
    }
  }
}

void test_symbolic_index_handling4(int choice) {
  char c;
  c = f(choice)[four_byte_signed_index]; // expected-warning{{Indexing array with type 'int' cannot cover the whole range of the array's index set, which results in memory waste. Consider using a type with greater maximum value}}
}

