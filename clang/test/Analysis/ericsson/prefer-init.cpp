// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.cpp.style.PreferInit -Wno-everything -verify %s
//alpha
struct Y {
    Y() {}
};

struct X {
    int n;
    Y y;
    Y y2;

    X() {
        n = 3;      // control
        y = Y() ; // expected-warning {{Prefer using initialization list in constructors to using assignment operators}} // (1)

        if (n > 5) y2 = Y(); // control
    }
};
