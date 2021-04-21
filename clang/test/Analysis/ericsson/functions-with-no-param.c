// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.misrac.FunctionsWithNoParam -Wno-everything -verify %s


int test1();// expected-warning {{Functions with no parameters shall be declared and defined with void parameter list}}

int test2(){}// expected-warning {{Functions with no parameters shall be declared and defined with void parameter list}}

int test3(/*void*/);// expected-warning {{Functions with no parameters shall be declared and defined with void parameter list}}

void test4(void);

// K&R definition of a function
int foo(a)
    int a; // parameter types were declared separately
{
    // ...
    return 0;
}
