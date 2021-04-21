// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.misrac.ExternalArrayWithUnknownSize -Wno-everything -verify %s
extern int a1[];// expected-warning {{External array with unknown size}} 

int a2[] = {1,2};

int a3[5];

extern int a4[5];

extern int a5[] = {1,2};

static int a6[5];

static int a7[] = {1,2};

void fun1(int p[]) {
}

void fun2(int p[5]) {
}

void fun3(int p[]);

void fun4(int p[5]);

int main() {
  return 0;
}
