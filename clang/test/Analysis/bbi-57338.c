// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -verify

void clang_analyzer_printState();
void clang_analyzer_eval(int);

void f(int a0, int b0, int c)
{
    int a1 = a0 - b0;
    int b1 = (unsigned)a1 + c;
    if (c == 0) {
        int d = 7L / b1;
        clang_analyzer_eval(a0 - b0 != 0); // expected-warning{{TRUE}}
    }
}
