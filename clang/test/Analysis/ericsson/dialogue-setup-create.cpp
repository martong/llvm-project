// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.mtas.DialogueSetupCreate -Wno-everything -verify %s
class Dicos_Setup {
public:
  void setup() {}
};

class SimpleClass {
public:
  void f() {}
};

// Case 0: Warning
class X {
  Dicos_Setup *d;
public:
  void createSetup() { d = new Dicos_Setup(); }// expected-warning {{Instances of Dialogue *_Setup classes must be created in systemStarted() for static processes and in start() for dynamic processes}}
};

class Y {
public:
  void callTo() {
    X x;
    x.createSetup();
  }
};

class V0 {
public:
  void start() {
    Y y;
    y.callTo();
  }
  void systemStarted() {}
};

// Case 1: OK
class X2 {
  Dicos_Setup *d;

public:
  void createSetup() { d = new Dicos_Setup(); }
};

class Y2 {
public:
  void callTo() {
    X2 x;
    x.createSetup();
  }
};

class V1 {
public:
  void start() {}
  void systemStarted() {
    Y2 y;
    y.callTo();
  }
  void noCallFromValidPlace() {}
};

// Case 2: Warning
class V2 {
public:
  void systemStarted() {}
  // Test indirect recursion
  void bar() { foo(); }
  void foo() { bar(); Dicos_Setup *d = new Dicos_Setup(); }// expected-warning {{Instances of Dialogue *_Setup classes must be created in systemStarted() for static processes and in start() for dynamic processes}}
};

// Case 3: OK
class V3 {
public:
  void start() { Dicos_Setup *d = new Dicos_Setup(); }
};

// Case 4: Warning
class V4 {
public:
  void start() {}
  // Test direct recursion
  void foo() { foo(); Dicos_Setup *d = new Dicos_Setup(); }// expected-warning {{Instances of Dialogue *_Setup classes must be created in systemStarted() for static processes and in start() for dynamic processes}}
};

// Case 5: OK
class V5 {
public:
  void start() {}
  void systemStarted() { bar(); }
  void foot() { Dicos_Setup *d = new Dicos_Setup(); }
  void bar() {
    foot();
    foo(2);
  }
  int foo(int x) { return x; }
};

// Case 6: Warning
class V6 {
public:
  void start() { bar(); }
  void systemStarted() { bar(); }
  void foot() { Dicos_Setup *d = new Dicos_Setup(); }// expected-warning {{Instances of Dialogue *_Setup classes must be created in systemStarted() for static processes and in start() for dynamic processes}}
  void bar() {
    foot();
    foo(2);
  }
  int foo(int x) { return x; }
  void noCallFromValidPlace() {}
};

// Case 7: Warning
class V7 {
public:
  void start() {}
  void systemStarted() { bar(); }
  void foot() { Dicos_Setup *d = new Dicos_Setup(); }// expected-warning {{Instances of Dialogue *_Setup classes must be created in systemStarted() for static processes and in start() for dynamic processes}}
  void bar() {
    foot();
    foo(2);
  }
  int foo(int x) { return x; }
  void noCallFromValidPlace() { foot(); }
};

// Case 8: OK
class V8 {
public:
  void start() { bar(); }
  void foot() { Dicos_Setup *d = new Dicos_Setup(); }
  void bar() {
    foot();
    foo(2);
  }
  int foo(int x) { return x; }
  void noCallFromValidPlace() {}
};

// Case 9: Warning
class V9 {
public:
  void start() {}
  void foot() { Dicos_Setup *d = new Dicos_Setup(); }// expected-warning {{Instances of Dialogue *_Setup classes must be created in systemStarted() for static processes and in start() for dynamic processes}}
  void bar() {
    foot();
    foo(2);
  }
  int foo(int x) { return x; }
  void noCallFromValidPlace() { foot(); }
};

// Case 10: warning
class a_Setup {};

class V10 {
public:
  void nostart() { a_Setup d; }// expected-warning {{Instances of Dialogue *_Setup classes must be created in systemStarted() for static processes and in start() for dynamic processes}}
  void start() {}
};

// Case 11: OK (not a Setup)
class V33 {
public:
  void nostart() { SimpleClass d; }
  void start() { V10 v; }
};

class FLOAT {
public:
  FLOAT(int a) {}
};

class BAR {
  void bar() { FLOAT *v = new FLOAT(2); }
};
