// RUN: %clang_analyze_cc1 -std=c++11 \
// RUN: -analyzer-checker=core,cplusplus,alpha.ericsson.cpp.IteratorOutOfRange \
// RUN: -analyzer-config aggressive-binary-operation-simplification=true \
// RUN: -analyzer-config c++-container-inlining=false %s \
// RUN: -analyzer-output=text -verify

// expected-no-diagnostics

template <typename a> struct b { typedef a &c; };
template <typename> struct d;
template <typename a> struct d<a[]> { typedef a c; };
template <typename a> using e = typename d<a>::c;
template <typename> struct f;
template <long, typename a> using g = typename f<a>::c;
template <typename...> class h;
template <typename i> struct j {
  static i &k(j &l) { return l.m; }
  i m;
};
template <long, typename...> struct n;
template <long o, typename i, typename... p> struct n<o, i, p...> : j<i> {};
template <typename q, typename aa> class h<q, aa> : public n<0, q> {};
template <typename i, typename... p> struct f<h<i, p...>> { typedef i c; };
template <int ab, typename i> i &r(n<ab, i> &l) { return n<ab, i>::k(l); }
template <int ab, typename... ac> g<ab, h<ac...>> &ad(h<ac...> &l) {
  return r<ab>(l);
}
template <typename a> class s {
  template <typename t> struct I { using c = t *; };

public:
  using ae = typename I<a>::c;
  s(ae l) { ag() = l; }
  ae &ag() { return ad<0>(ah); }
  h<ae, int> ah;
};
template <typename a, typename = a> class ai {};
template <typename a, typename aj> class ai<a[], aj> {
  s<a> ah;

public:
  using ae = typename s<a>::ae;
  using ak = a;
  template <typename t> ai(t l) : ah(l) {}
  typename b<ak>::c operator[](long l) { return ad()[l]; }
  ae ad() { return ah.ag(); }
};
template <typename a, typename aj>
void operator==(ai<a, aj> &, decltype(nullptr));
template <typename> struct J;
template <typename a> struct J<a[]> { typedef ai<a[]> an; };
template <typename a> typename J<a>::an ao(long l) { return new e<a>[l]; }
using aq = ai<int>;
void at() {
  auto a = ao<aq[]>(2);
  a[0] == nullptr;
}
