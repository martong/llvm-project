// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.MemsizeParamOverload -analyzer-config alpha.ericsson.MemsizeParamOverload:AnyTypedefType=true %s -verify

namespace std
{
typedef unsigned      uint32_t;
typedef unsigned long uint64_t;
typedef unsigned long size_t;
}

typedef std::uint32_t UInt32TTypedef;
typedef std::size_t SizeTTypedef;

void f(std::uint32_t) {}  // expected-note{{candidate function}}
                          // expected-note@-1{{candidate function}}
                          // expected-note@-2{{candidate function}}
void f(std::uint64_t) {}  // expected-note{{candidate function}}
                          // expected-note@-1{{candidate function}}
                          // expected-note@-2{{candidate function}}
void f(int*) {}
void f(short) {}

struct S {
  void g(char, std::uint32_t) {}  // expected-note{{candidate function}}
  void g(char, std::uint64_t) {}  // expected-note{{candidate function}}
  void g(char, int*) {}
};

int main()
{
  f(std::size_t()); // expected-warning {{Overload resolution of this call depends on the architecture (because of parameter 1). Two or more functions are defined with the same name, but architecture dependent arguments}}
  f(new int); // nowarning

  S s;
  s.g(0, std::size_t()); // expected-warning {{Overload resolution of this call depends on the architecture (because of parameter 2). Two or more functions are defined with the same name, but architecture dependent arguments}}
  s.g(0, new int); // nowarning

  int i = 42;
  f(std::uint32_t()); // nowarning
  f(static_cast<std::uint32_t>(i)); // nowarning
  f(static_cast<UInt32TTypedef>(42)); // expected-warning {{Overload resolution of this call depends on the architecture (because of parameter 1). Two or more functions are defined with the same name, but architecture dependent arguments}}
  f(static_cast<SizeTTypedef>(42)); // expected-warning {{Overload resolution of this call depends on the architecture (because of parameter 1). Two or more functions are defined with the same name, but architecture dependent arguments}}

  return 0;
}

