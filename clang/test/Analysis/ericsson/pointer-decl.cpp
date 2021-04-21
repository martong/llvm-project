// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.linuxkernelstyle.PointerDecl -Wno-everything -verify %s

int a,b;
char * linux_banner;// expected-warning {{Write * adjacent to the variable or function name instead of the type name}} //bad
char *linux_banner2;//good
unsigned long long memparse(char * ptr/*bad*/, char * *retptr/*good*/);// expected-warning {{Write * adjacent to the variable or function name instead of the type name}}
char * match_strdup(char *s);// expected-warning {{Write * adjacent to the variable or function name instead of the type name}} //bad
typedef char* myptr_t;//good
myptr_t p;
myptr_t *p2;//good
myptr_t* p3;// expected-warning {{Write * adjacent to the variable or function name instead of the type name}} //bad
int* p4,* p5; // expected-warning {{Write * adjacent to the variable or function name instead of the type name}} expected-warning {{Write * adjacent to the variable or function name instead of the type name}} //bad

struct foobar {
  operator const char *() { return 0; }
};

int main (void){
  int * linux_banne,x;// expected-warning {{Write * adjacent to the variable or function name instead of the type name}} //bad
  if (1){
    int a=3;
  }
}

class X {
  void* f1(); // expected-warning {{Write * adjacent to the variable or function name instead of the type name}}
  void *f2();
};
void* X::f1() { // expected-warning {{Write * adjacent to the variable or function name instead of the type name}}
}
void *X::f2() {
}


// No warnings at implicit pointer declarations related to lambdas.

class C1 {
public:
  void f();
};

class C2 {
  void f1(int *p);
  void f2();
  void f3();
  C1 *ptr;
};

void C2::f1(int *p) {
  auto L = [p]() -> void { // no warning at 'p'
  };
}

void C2::f2() {
  auto L = [&]() -> void {
    ptr->f(); // no warning at 'ptr'
  };
}

void C2::f3() {
  auto L = [&]() -> void {
    f2(); // no warning at 'f2'
  };
}
