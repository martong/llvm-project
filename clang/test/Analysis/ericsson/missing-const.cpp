// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.cpp.style.MissingConst -analyzer-config ericsson.cpp.style.MissingConst:CheckValueParams=true -Wno-everything -verify %s

/* <options>
[options]
check_value_params=true
</options> */

#include "Inputs/system-header-simulator-cxx.h"
#include "Inputs/bugs-in-system-header.h"

void trivial_test() {
    int a = 2;
    int b = 3;// expected-warning {{This declaration could be const}}

    if (b == 3)
        ++a;
}

void modify_through_reference() {
    int a = 5;
    int& b = a;
    int c = 3;// expected-warning {{This declaration could be const}}

    if (c > 2)
        b = 2;
}

void modify_through_pointer() {
    int a = 5;
    int* b = &a;
    int c = 3;// expected-warning {{This declaration could be const}}

    if (c > 2)
        *b = 2;
}

void parameter(int b) {// expected-warning {{This declaration could be const}}
    if (b)
        ;
}

void unknown_function(int& a, const int& b);

void pass_by_reference() {
    int a = 5;
    int b = 3;// expected-warning {{This declaration could be const}}
    unknown_function(a, b);
}

struct X {
    int x, y, z;

    void trivial_test_in_class() {
        x = 5;
        int a = 2;
        int b = 3;// expected-warning {{This declaration could be const}}

        if (b == 3)
            ++a;
    }

    void modify_through_reference_in_class() {
        int a = 5;
        int& b = a;
        int c = 3;// expected-warning {{This declaration could be const}}

        if (c > 2)
            b = 2;

        trivial_test_in_class();
    }

    void modify_through_pointer_in_class() const {
        int a = 5;
        int* b = &a;
        int c = 3;// expected-warning {{This declaration could be const}}

        if (c > 2)
            *b = 2;
    }

    void parameter_in_class(int b) { // expected-warning {{This declaration could be const}} expected-warning {{This declaration could be const}}

        if (b) {
            int& a = z;
            a = 3;
        }
    }

    void pass_by_reference_in_class() const {
        int a = 5;
        int b = 3;// expected-warning {{This declaration could be const}}
        unknown_function(a, b);
    }
};

void range_based_for() {
  // Using range-based 'for' results in generation of hidden declarations.
  // These are variables for begin, end, and range, that are theoretically
  // detectable by the checker, at locations of the ':' and 'v' character.
  // This test ensures that no such variables are found.
  const std::vector<int> v;
  for (int i : v) { // no-warning
    i = 7;
  }
}

// The checker should not produce warnings for variables with dependent
// type. It is not known here if the called functions are const or not.
// In this code the 'something' can be a non-const function dependent
// on the type of T at instantiations.
template<class T>
void no_warning_on_dependent_type(std::vector<T> &v) { // no-warning for 'v'
  auto it = v.begin(); // no-warning for 'it'
  it->something();
  T t; // no-warning for 't'
  t.something();
}

void macro_in_system_header() {
  TEST_MISSING_CONST(1);
}
