// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.cpp.OStreamFormat -verify -std=c++11 %s

#include "Inputs/system-header-simulator-cxx-iostream.h"


class StreamState {
public:
  StreamState(std::ostream &out)
      : m_out(out), m_fmt(out.flags()), m_prec(out.precision()) {}

  ~StreamState() {
    m_out.precision(m_prec);
    m_out.flags(m_fmt);
  }

private:
  std::ostream &m_out;
  std::ios_base::fmtflags m_fmt;
  std::streamsize m_prec;
};

void test1(int i) {
  std::cout << std::hex << i;
} // expected-warning{{Possibly forgotten ostream format modification in scope}}

void test2(int i) { std::cout << std::hex << i << std::dec; } // OK.

void test3(int i) {
  std::cout << std::hex << i;
  std::cout << std::dec;
} // ok

void test4(float f) {
  std::cout << std::setprecision(2)
            << f; // The stream state is chaged, but not restored.
} // expected-warning{{Possibly forgotten ostream format modification in scope}}

int test5() {
  std::cout.setf(std::ios::hex,
                 std::ios::basefield); // Set hex as the basefield.
  std::cout.setf(std::ios::showbase);  // Activating showbase.
  std::cout << 100 << '\n';
  std::cout.unsetf(std::ios::showbase); // Deactivating showbase.
  std::cout << 100 << '\n';
  return 0; // The stream state is chaged, but not restored.
} // expected-warning@-1{{Possibly forgotten ostream format modification in scope}}

void test6(const char *results) {
  StreamState ss(std::cout);
  std::cout << std::setiosflags(std::ios::fixed)
            << std::setprecision(6); // The stream state is set here.
  std::cout << results << std::endl;
} // OK, stream state is recovered here.

void test7(int i) {
  std::cout << std::hex << i;
  std::cout.setf(std::ios::dec);
} // OK.

void test8(float i) {
  std::cout << std::setprecision(12) << i;
  std::cout.precision(6);
} // OK.

void test9(float i) {
  std::cout.precision(6);
  std::cout << std::setprecision(12) << i;
} // expected-warning{{Possibly forgotten ostream format modification in scope}}

void test10(float i) {
  std::cout.precision(12);
  std::cout << std::setprecision(6) << i;
} // OK.

