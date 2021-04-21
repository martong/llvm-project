// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.cpp.style.LargeObjectPassed -Wno-everything -verify %s

struct Foo {
    char buffer[129];
};

//PASS_BY_VALUE
struct PASS_BY_VALUE_big {
    int a[20];
    int b[20];
    int c[20];
};

void PASS_BY_VALUE_test(PASS_BY_VALUE_big b) {
    // Warning: passing by value, 240 bytes
}

void bar(Foo f) {}
void baz(const Foo& f) {}
void bah(Foo& f) {}
void boo(Foo* f) {}
void meh(const Foo f, Foo& of) {}

void blah(unsigned int n) { n++; }

int main(int argc, const char** argv) {
    Foo f;
    Foo* fp = &f;

    bar(f);// expected-warning {{Passing large object by value (size: 129 bytes)}}
    baz(f);
    bah(f);
    boo(fp);
    meh(f, f);// expected-warning {{Passing large object by value (size: 129 bytes)}}
    blah(1);

    PASS_BY_VALUE_big bigs;
    PASS_BY_VALUE_test(bigs);// expected-warning {{Passing large object by value (size: 240 bytes)}}

    return 0;
}

