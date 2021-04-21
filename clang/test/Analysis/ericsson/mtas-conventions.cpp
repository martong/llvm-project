// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.mtas.MtasConventions -Wno-everything -verify %s

#include "Inputs/MtasConventions.hh"

int a, b;

class xX {}; // expected-warning {{Type names should start with an uppercase letter}} // (1)

class Yy {
  public:
    Yy() {}

  private:
    void CsigaBiga() {} // expected-warning {{Function and method names should start with a lowercase letter}} // (2)

  public: // expected-warning {{The order of visibility in a class should be: public, protected, private (whereas here 'private' is followed by this 'public')}} // (3)
    bool isProperty() {}

    bool property() {} // expected-warning {{Methods returning bool should be prefixed with 'is'}} // (4)
};

enum aA { // expected-warning {{Type names should start with an uppercase letter}} // (5)
    AAA,
    bbb // expected-warning {{Constants should only contain uppercase letters}} // (6)
};

template <typename TA>// expected-warning {{Template parameter names should consist of a single uppercase letter}}
// (7)
struct Foobar {};

int main() {
    const int FOO = 2;
    const int bar = 1; // expected-warning {{Constants should only contain uppercase letters}} // (8)

    ::a = 2;
    int q = 2.5;  // expected-warning {{Implicit casts are disallowed: use explicit cast to convert type 'double' to 'int'}} // (9)
    b = 3;     // expected-warning {{Global variables should always be referenced absolutely, i.e. with the '::' prefix}} // (10)

    bool isFoobar;
    bool foobar; // expected-warning {{Boolean variable names should be prefixed with 'is'}} // (11)

    for (;;) // expected-warning {{Only while(true) constructs should be used for infinite loops}} // (12)
        ;
	while (1) // expected-warning {{Invalid character is used near this position}} expected-warning {{Only while(true) constructs should be used for infinite loops}} // (13)
        ;

    if (::b) // expected-warning {{Avoid implicit tests for zero values (converting type 'int' to boolean)!}} // (14)
        ;

    if (isFoobar = true) // expected-warning {{Assignments should be avoided in conditions}} // (15)
        ;

    do { // expected-warning {{Do while loops should be avoided}} // (16)
    } while (false);

    return 0;
}

typedef int foobaz;// expected-warning {{Type names should start with an uppercase letter}}
