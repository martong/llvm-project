// RUN: %clang_analyze_cc1 -fcxx-exceptions -analyzer-checker=ericsson.cpp.style.ReduceScope -Wno-everything -verify %s


void f () {
    int a;// expected-warning {{The scope of variable 'a' can be reduced}}
    {
        int b;
        a = 2;
        {
            b = 3;
            a = 1;
        }
        b = 0;
    }

    if (int i = 5) {
        i = 3;
    }
}

void g() {
	int a = 3;
	int c = 1;

	switch(c) {
		case 0:
			++a;
			break;
		case 1:
			--a;
			break;
	}
}


#define HUGEMACRO(X) { \
    {{{{X}}}}       \
                    \
                    \
                    \
                    \
    }

void h() {
    int i;

    HUGEMACRO(++i;);
}

void ii(int& i);

void i() {
    int j = 0;

    while(true)
    {
        ii(j);
    }
}

void hh() {

  try {
    throw 2;
  }
  catch (int i) {
    int a = 5;
    {
      a = i;
    }
    ++a;
  }
}

void gg(int b) {
  int a = 5;
  {
    a = b;
  }
  ++a;
}
