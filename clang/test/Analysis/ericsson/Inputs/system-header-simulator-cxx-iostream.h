// Like the compiler, the static analyzer treats some functions differently if
// they come from a system header -- for example, it is assumed that system
// functions do not arbitrarily free() their parameters, and that some bugs
// found in system headers cannot be fixed by the user and should be
// suppressed.
#pragma clang system_header

namespace std {
int printf();
}

namespace std {
typedef unsigned streamsize;

namespace ios {
int boolalpha;
int dec;
int fixed;
int hex;
int internal;
int left;
int oct;
int right;
int scientific;
int showbase;
int showpoint;
int showpos;
int skipws;
int unitbuf;
int uppercase;
int adjustfield;
int basefield;
int floatfield;
}

class ios_base {
public:
  typedef int fmtflags;
  fmtflags m_fmt;
  fmtflags flags() const;
  fmtflags flags(fmtflags);
  fmtflags setf(fmtflags);
  fmtflags setf(fmtflags, fmtflags);
  void unsetf(fmtflags);
  streamsize precision() const;
  streamsize precision(streamsize);
  streamsize width() const;
  streamsize width(streamsize);
};

template <class T> class basic_ios : public ios_base {};

// Simple manipulators.

ios_base &boolalpha(ios_base &);
ios_base &noboolalpha(ios_base &);
ios_base &showbase(ios_base &);
ios_base &noshowbase(ios_base &);
ios_base &showpoint(ios_base &);
ios_base &noshowpoint(ios_base &);
ios_base &showpos(ios_base &);
ios_base &noshowpos(ios_base &);
ios_base &skipws(ios_base &);
ios_base &noskipws(ios_base &);
ios_base &uppercase(ios_base &);
ios_base &nouppercase(ios_base &);
ios_base &unitbuf(ios_base &);
ios_base &nounitbuf(ios_base &);
ios_base &internal(ios_base &);
ios_base &left(ios_base &);
ios_base &right(ios_base &);
ios_base &dec(ios_base &);
ios_base &hex(ios_base &);
ios_base &oct(ios_base &);
ios_base &fixed(ios_base &);
ios_base &scientific(ios_base &);
ios_base &hexfloat(ios_base &);
ios_base &defaultfloat(ios_base &);


template <class T> class basic_ostream : public basic_ios<T> {
public:
  basic_ostream &operator<<(int);
  basic_ostream &operator<<(float);
  basic_ostream &operator<<(double);
  basic_ostream &operator<<(const char *);
  basic_ostream &operator<<(const basic_ostream &);
  basic_ostream &operator<<(basic_ostream &(*)(basic_ostream &));
  basic_ostream &operator<<(basic_ios<T> &(*)(basic_ios<T> &));
  basic_ostream &operator<<(ios_base &(*)(ios_base &));
};

template <class T> basic_ostream<T> &endl(basic_ostream<T> &);

template <class T> class basic_istream : public basic_ios<T> {
public:
  basic_istream &operator>>(int);
  basic_istream &operator>>(float);
  basic_istream &operator>>(double);
  basic_istream &operator>>(const char *);
  basic_istream &operator>>(const basic_istream &);
  basic_istream &operator>>(basic_istream &(*)(basic_istream &));
  basic_istream &operator>>(basic_ios<T> &(*)(basic_ios<T> &));
  basic_istream &operator>>(ios_base &(*)(ios_base &));
};

// Complex, parametric manipulators.

class resetiosflags_manip {
public:
  explicit resetiosflags_manip(ios_base::fmtflags);
  template <class T>
  friend basic_istream<T> &operator>>(basic_istream<T> &,
                                      const resetiosflags_manip &);
  template <class T>
  friend basic_ostream<T> &operator<<(basic_ostream<T> &,
                                      const resetiosflags_manip &);
};

class setiosflags_manip {
public:
  explicit setiosflags_manip(ios_base::fmtflags);
  template <class T>
  friend basic_istream<T> &operator>>(basic_istream<T> &,
                                      const setiosflags_manip &);
  template <class T>
  friend basic_ostream<T> &operator<<(basic_ostream<T> &,
                                      const setiosflags_manip &);
};

class setprecision_manip {
  int n;

public:
  explicit setprecision_manip(ios_base::fmtflags);
  template <class T>
  friend basic_istream<T> &operator>>(basic_istream<T> &,
                                      const setprecision_manip &);
  template <class T>
  friend basic_ostream<T> &operator<<(basic_ostream<T> &,
                                      const setprecision_manip &manip);
};

class setbase_manip {
public:
  explicit setbase_manip(int);
  template <class T>
  friend basic_istream<T> &operator>>(basic_istream<T> &,
                                      const setbase_manip &);
  template <class T>
  friend basic_ostream<T> &operator<<(basic_ostream<T> &,
                                      const setbase_manip &);
};

template <class T> class setfill_manip {
public:
  explicit setfill_manip(T);
  friend basic_istream<T> &operator>>(basic_istream<T> &,
                                      const setfill_manip &);
  friend basic_ostream<T> &operator<<(basic_ostream<T> &,
                                      const setfill_manip &);
};

class setw_manip {
public:
  explicit setw_manip(int);
  template <class T>
  friend basic_istream<T> &operator>>(basic_istream<T> &, const setw_manip &);
  template <class T>
  friend basic_ostream<T> &operator<<(basic_ostream<T> &, const setw_manip &);
};

resetiosflags_manip resetiosflags(ios_base::fmtflags fmtf) {
  return resetiosflags_manip(fmtf);
}

setiosflags_manip setiosflags(ios_base::fmtflags fmtf) {
  return setiosflags_manip(fmtf);
}

setprecision_manip setprecision(int prec) { return setprecision_manip(prec); }

setbase_manip setbase(int base) { return setbase_manip(base); }

template <class T> setfill_manip<T> setfill(T fill) {
  return setfill_manip<T>(fill);
}

setw_manip setw(int width) { return setw_manip(width); }

typedef basic_ostream<char> ostream;
typedef basic_istream<char> istream;

extern istream cin;
extern ostream cout;
extern ostream cerr;
extern ostream clog;
}

