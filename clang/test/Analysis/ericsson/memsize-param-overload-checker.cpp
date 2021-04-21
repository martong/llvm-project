// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.MemsizeParamOverload %s -verify

namespace std
{
typedef unsigned      uint32_t;
typedef unsigned long uint64_t;
typedef unsigned long size_t;
}

typedef std::uint32_t UInt32TTypedef;
typedef std::size_t SizeTTypedef;

void f(std::uint32_t) {}  // expected-note{{candidate function of call at}}
                          // expected-note@-1{{candidate function of call at}}
                          // expected-note@-2{{candidate function of call at}}
void f(std::uint64_t) {}  // expected-note{{candidate function of call at}}
                          // expected-note@-1{{candidate function of call at}}
                          // expected-note@-2{{candidate function of call at}}
void f(int*) {}
void f(short) {}

struct S {
  void g(char, std::uint32_t) {}  // expected-note{{candidate function of call at}}
  void g(char, std::uint64_t) {}  // expected-note{{candidate function of call at}}
  void g(char, int*) {}
};

struct T1 {
  static void h(std::uint32_t) {}
};

struct T2 {
  static void h(std::uint64_t) {}
};

void k(std::uint32_t, int) {}
void k(std::uint64_t, int, int) {}

void l(std::uint32_t, int) {}  // expected-note{{candidate function of call at}}
void l(std::uint64_t, int, int = 42) {}  // expected-note{{candidate function of call at}}

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
  f(static_cast<UInt32TTypedef>(42)); // nowarning
  f(static_cast<SizeTTypedef>(42)); // expected-warning {{Overload resolution of this call depends on the architecture (because of parameter 1). Two or more functions are defined with the same name, but architecture dependent arguments}}
  f((SizeTTypedef)42); // expected-warning {{Overload resolution of this call depends on the architecture (because of parameter 1). Two or more functions are defined with the same name, but architecture dependent arguments}}

  T1::h(std::size_t()); // nowarning
  T2::h(std::size_t()); // nowarning

  k(std::size_t(), 42); // nowarning
  k(std::size_t(), 42, 43); // nowarning
  l(std::size_t(), 42); // expected-warning {{Overload resolution of this call depends on the architecture (because of parameter 1). Two or more functions are defined with the same name, but architecture dependent arguments}}
  l(std::size_t(), 42, 43); // nowarning

  return 0;
}

