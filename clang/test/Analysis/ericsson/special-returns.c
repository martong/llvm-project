// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.ericsson.statisticsbased.SpecialReturnValue -analyzer-config alpha.ericsson.statisticsbased:APIMetadataPath="%S"/Inputs -verify %s -analyzer-output=text
// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.ericsson.statisticsbased.SpecialReturnValue -analyzer-config alpha.ericsson.statisticsbased:APIMetadataPath="%S" %s 2>&1 | FileCheck %s -check-prefix=BADPATH
// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.ericsson.statisticsbased.SpecialReturnValue %s 2>&1 | FileCheck %s -check-prefix=BADPATH

// BADPATH: warning: Could not find API data for alpha.ericsson.statisticsbased.SpecialReturnValue, skipping checks

#define NULL 0

int negative_return();
int nonnegative_return();
int *null_return();
int *nonnull_return();

void good_negative() {
  int n = negative_return();
  if (n < 0)
    return;
  int v[n]; // no-warning
}

void bad_negative() {
  int n = negative_return(); // expected-note{{Assuming the return value of negative_return() is < 0 (based on call statistics)}}
                             // expected-note@-1{{'n' initialized here}}
  int v[n]; // expected-warning {{Declared variable-length array (VLA) has negative size}}
            // expected-note@-1{{Declared variable-length array (VLA) has negative size}}
}

void nonnegative() {
  int n = nonnegative_return();
  int v[n]; // no-warning
}

void good_null() {
  int *p = null_return();
  if (p == NULL)
    return;
  int n = *p; // no-warning
}

void bad_null() {
  int *p = null_return(); // expected-note{{Assuming the return value of null_return() is == 0 (based on call statistics)}}
                          // expected-note@-1{{Assuming pointer value is null}}
                          // expected-note@-2{{'p' initialized here}}
  int n = *p; //expected-warning {{Dereference of null pointer (loaded from variable 'p')}}
              //expected-note@-1{{Dereference of null pointer (loaded from variable 'p')}}
}

void nonnull() {
  int *p = nonnull_return();
  int n = *p; // no-warning
}
