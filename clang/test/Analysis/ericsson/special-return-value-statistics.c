// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.statisticscollector.SpecialReturnValue %s -verify
// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.statisticscollector.SpecialReturnValue %s 2>&1 | "%S"/../../../utils/ericsson/gen_yaml_for_special_return_values.py | FileCheck %s

int negative_return();
int nonnegative_return();
int *null_return();
int *nonnull_return();

#define NULL 0

void checked_negative1() {
  if (negative_return() < 0) {} // expected-warning{{"c:@F@negative_return",1,0}}
}

void checked_negative2() {
  if (negative_return() >= 0) {} // expected-warning{{"c:@F@negative_return",1,0}}
}

void checked_negative3_4() {
  int n = negative_return(); // expected-warning{{"c:@F@negative_return",1,0}}
  if (n < 0) {}
  if (negative_return() == n) {} // expected-warning{{"c:@F@negative_return",1,0}}
}

void checked_negative5_6() {
  int n = negative_return(); // expected-warning{{"c:@F@negative_return",1,0}}
  if (n >= 0) {}
  if (negative_return() >= n) {} // expected-warning{{"c:@F@negative_return",1,0}}
}

void unchecked_negative() {
  int n = negative_return(); // expected-warning{{"c:@F@negative_return",0,0}}
}

void checked_null1() {
  if (null_return() == NULL) {} // expected-warning{{"c:@F@null_return",0,1}}
}

void checked_null2() {
  if (null_return() != NULL) {} // expected-warning{{"c:@F@null_return",0,1}}
}

void checked_null3_4() {
  int *n = null_return(); // expected-warning{{"c:@F@null_return",0,1}}
  if (n == NULL) {}
  if (null_return() == n) {} // expected-warning{{"c:@F@null_return",0,1}}
}

void checked_null5_6() {
  int *n = null_return(); // expected-warning{{"c:@F@null_return",0,1}}
  if (n != NULL) {}
  if (null_return() == n) {} // expected-warning{{"c:@F@null_return",0,1}}
}

void unchecked_null() {
  int *n = null_return(); // expected-warning{{"c:@F@null_return",0,0}}
}

// CHECK: #
// CHECK-NEXT: # SpecialReturn metadata format 1.0
// CHECK: {name: "c:@F@negative_return", relation: LT, value: 0} 
// CHECK: {name: "c:@F@null_return", relation: EQ, value: 0} 
