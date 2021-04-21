// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.statisticscollector.ReturnValueCheck %s -verify 
// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.statisticscollector.ReturnValueCheck %s 2>&1 | "%S"/../../../utils/ericsson/gen_yaml_for_return_value_checks.py | FileCheck %s

int to_check();
int not_to_check();

int check(int);

void assign() {
  int n = to_check(); // expected-warning{{c:@F@to_check,0}}
}

void cond() {
  if(to_check()) {} // expected-warning{{c:@F@to_check,0}}
}

void loop1() {
  while(to_check()) {} // expected-warning{{c:@F@to_check,0}}
}

void loop2() {
  do {} while(to_check()); // expected-warning{{c:@F@to_check,0}}
}

void loop3() {
  for(;to_check();); // expected-warning{{c:@F@to_check,0}}
}

void compare1() {
  if (to_check() >= 0) {} // expected-warning{{c:@F@to_check,0}}
}

void compare2() {
  if (to_check() < 0) {} // expected-warning{{c:@F@to_check,0}}
}

void arg() {
  check(to_check()); // expected-warning{{c:@F@to_check,0}}
                     // expected-warning@-1{{c:@F@check,1}}
}

void oops() {
  to_check();// expected-warning{{c:@F@to_check,1}}
}

void ok() {
  not_to_check();// expected-warning{{c:@F@not_to_check,1}}
}

void unnecessary() {
  if(not_to_check()) {}// expected-warning{{c:@F@not_to_check,0}}
}

void switch_case(){
  int i;
  switch (to_check()){// expected-warning{{c:@F@to_check,0}}
    case 0: not_to_check();break;// expected-warning{{c:@F@not_to_check,1}}
    case 1: i = to_check();break;// expected-warning{{c:@F@to_check,0}}
  }
}

void void_func();

void return_void() {
  return void_func();// no-warning
}

// CHECK: #
// CHECK-NEXT: # UncheckedReturn metadata format 1.0
// CHECK: - c:@F@to_check
