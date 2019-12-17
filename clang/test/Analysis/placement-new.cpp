// RUN: %clang_analyze_cc1 -std=c++11 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=cplusplus.NewDelete \
// RUN:   -analyzer-checker=cplusplus.PlacementNew \
// RUN:   -analyzer-output=text -verify \
// RUN:   -triple x86_64-unknown-linux-gnu

#include "Inputs/system-header-simulator-cxx.h"

void f() {
  short s; // expected-note-re {{'s' declared{{.*}}}}
  long *lp = ::new (&s) long; // expected-warning{{Argument of default placement new provides storage capacity of 2 bytes, but the allocated type requires storage capacity of 8 bytes}} expected-note 3 {{}}
  (void)lp;
}

namespace testArrayNew {
void f() {
  short s; // expected-note-re {{'s' declared{{.*}}}}
  char *buf = ::new (&s) char[8]; // expected-warning{{Argument of default placement new provides storage capacity of 2 bytes, but the allocated type requires storage capacity of 8 bytes}} expected-note 3 {{}}
  (void)buf;
}
} // namespace testArrayNew

namespace testBufferInOtherFun {
void f(void *place) {
  long *lp = ::new (place) long; // expected-warning{{Argument of default placement new provides storage capacity of 2 bytes, but the allocated type requires storage capacity of 8 bytes}} expected-note 1 {{}}
  (void)lp;
}
void g() {
  short buf; // expected-note-re {{'buf' declared{{.*}}}}
  f(&buf); // expected-note 2 {{}}
}
} // namespace testBufferInOtherFun

namespace testArrayBuffer {
void f(void *place) {
  long *lp = ::new (place) long; // expected-warning{{Argument of default placement new provides storage capacity of 2 bytes, but the allocated type requires storage capacity of 8 bytes}} expected-note 1 {{}}
  (void)lp;
}
void g() {
  char buf[2]; // expected-note-re {{'buf' initialized{{.*}}}}
  f(&buf); // expected-note 2 {{}}
}
} // namespace testArrayBuffer

namespace testGlobalPtrAsPlace {
void *gptr = nullptr;
short gs;
void f() {
  gptr = &gs; // expected-note {{Value assigned to 'gptr'}}
}
void g() {
  f(); // expected-note 2 {{}}
  long *lp = ::new (gptr) long; // expected-warning{{Argument of default placement new provides storage capacity of 2 bytes, but the allocated type requires storage capacity of 8 bytes}} expected-note 1 {{}}
  (void)lp;
}
} // namespace testGlobalPtrAsPlace

namespace testRvalue {
short gs;
void *f() {
  return &gs;
}
void g() {
  long *lp = ::new (f()) long; // expected-warning{{Argument of default placement new provides storage capacity of 2 bytes, but the allocated type requires storage capacity of 8 bytes}} expected-note 1 {{}}
  (void)lp;
}
} // namespace testRvalue

namespace testNoWarning {
void *f();
void g() {
  long *lp = ::new (f()) long;
  (void)lp;
}
} // namespace testNoWarning

namespace testPtrToArrayAsPlace {
void f() {
  //char *st = new char [8];
  char buf[3]; // expected-note-re {{'buf' initialized{{.*}}}}
  void *st = buf; // expected-note-re {{'st' initialized{{.*}}}}
  long *lp = ::new (st) long; // expected-warning{{Argument of default placement new provides storage capacity of 3 bytes, but the allocated type requires storage capacity of 8 bytes}} expected-note 1 {{}}
  (void)lp;
}
} // namespace testPtrToArrayAsPlace

namespace testHeapAllocatedBuffer {
void g2() {
  char *buf = new char[2]; // expected-note-re {{'buf' initialized{{.*}}}}
  long *lp = ::new (buf) long; // expected-warning{{Argument of default placement new provides storage capacity of 2 bytes, but the allocated type requires storage capacity of 8 bytes}} expected-note 1 {{}}
  (void)lp;
}
} // namespace testHeapAllocatedBuffer
