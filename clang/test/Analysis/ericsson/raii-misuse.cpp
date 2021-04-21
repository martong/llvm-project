// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.cpp.RaiiMisuse -Wno-everything -verify %s

#include "Inputs/system-header-simulator-cxx.h"

struct Foo
{
	Foo()
	{
		a = new bool(true);// expected-warning {{A resource allocated by the class ctor is not freed by the dtor}}
		b = new char[3] { 'm', 'o', 'o' };
		x = new int(5);
		y = 10;
	}

	~Foo()
	{
		delete[] b;
		delete[] x;// expected-warning {{The resource allocator and deallocator do not match}}
	}

	bool* a;
	char* b;
	int* x;
	int y;
};

struct Bar
{
	Bar()
	{
		z = new int(7);// expected-warning {{A resource allocated by the class ctor is not freed by the dtor}}
	}

	Bar(int t)
	{
		q = new bool(t > 10);// expected-warning {{A resource allocated by the class ctor is not freed by the dtor}}
		z = new int(6);// expected-warning {{A resource allocated by the class ctor is not freed by the dtor}}
	}

	~Bar() = default;

	int* z;
	bool* q;
};

struct Baz
{
	Baz()
	{
		z = new (buffer) int(7);
	}

	~Baz() = default;

	int* z;
  char buffer[sizeof(int)];
  };

struct ConstructorInitList {
  ConstructorInitList() : p(new int) {
    q = new int;
  }

  ~ConstructorInitList() {
    delete q;
    delete p;
  }

private:
  int *p, *q;
  };

struct BadConstructorInitList {
  BadConstructorInitList() : p(new int) {
    //FIXME: p is not deleted but the checker issues no warning!
    q = new int;
  }

  ~BadConstructorInitList() {
    delete q;
  }

private:
  int *p, *q;
  };

struct ConditionalInitialization {
  ConditionalInitialization(int n) {
    p = 0;
    if (n)
      p = new int;
    q = new int;
  }

  ~ConditionalInitialization() {
    delete q;
    delete p;
  }

private:
  int *p, *q;
};

struct UninitializedField {
  UninitializedField() {
    q = new int;
  }

  ~UninitializedField() {
    delete q;
    delete p;
  }

private:
  int *p, *q;
};


int main(int argc, const char** argv)
{
  Foo f;
	Bar br;
  Baz bz;
  ConstructorInitList cil;
  BadConstructorInitList bcil;
  ConditionalInitialization ci(0);
  UninitializedField uf;

	return 0;
}
