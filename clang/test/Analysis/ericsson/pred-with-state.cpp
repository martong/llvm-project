// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.cpp.PredWithState -Wno-everything -verify %s
struct Pred {
    bool operator()(int a) {
        f();
        return a == b;// expected-warning {{The result of the predicate relies on the state: 'Pred::b'}}
    }
    int b;

    void f() {}
};

struct Pred2 {
    Pred2(int i) : b(i) {}

    bool operator()(int a) { return a == b; }

    int& b;
};

struct Pred3 {
    const int b;

    Pred3() : b(5) {}

    bool operator()(int a) { return a == b; }
};

struct X {
    int a;
};

struct Pred4 {
    Pred4() {}

    bool operator()(X x) { return x.a == 5; }
};

struct Pred5 {
    Pred5(int i) : b(i) {}

    bool operator()(int a) {
        int c = f(b);
        return a == b;
    }

    int f(int) { return 0; }

    int& b;
};

struct Pred6 {
    Pred6(int i) : b(i) {}

    bool operator()(int a) { return a == b; }

    const int& b;
};

struct Pred7 {
    Pred7(int i) : b(i) {}

    bool operator()(int a) const { return a == b; }

    int b;
};
