// RUN: %clang_analyze_cc1 -std=c++11 \
// RUN: -analyzer-checker=core,cplusplus,alpha.ericsson.cpp.IteratorOutOfRange \
// RUN: -analyzer-config aggressive-binary-operation-simplification=true \
// RUN: -analyzer-config c++-container-inlining=false %s \
// RUN: -analyzer-output=text -verify

// RUN: %clang_analyze_cc1 -std=c++11 \
// RUN: -analyzer-checker=core,cplusplus,alpha.ericsson.cpp.IteratorOutOfRange \
// RUN: -analyzer-config aggressive-binary-operation-simplification=true \
// RUN: -analyzer-config c++-container-inlining=true -DINLINE=1 %s \
// RUN: -analyzer-output=text -verify

#include "Inputs/system-header-simulator-cxx.h"

extern void __assert_fail (__const char *__assertion, __const char *__file,
    unsigned int __line, __const char *__function)
     __attribute__ ((__noreturn__));
#define assert(expr) \
  ((expr)  ? (void)(0)  : __assert_fail (#expr, __FILE__, __LINE__, __func__))

void simple_good_end(const std::vector<int> &v) {
  auto i = v.end();
  if (i != v.end())
    *i; // no-warning
}

void simple_good_end_ptr(const std::vector<int> *v) {
  auto i = v->end();
  if (i != v->end())
    *i; // no-warning
}

void simple_good_end_ptr_ref(const std::vector<int> *&v) {
  auto i = v->end();
  if (i != v->end())
    *i; // no-warning
}

void simple_good_end_ptr_rref(const std::vector<int> *&&v) {
  auto i = v->end();
  if (i != v->end())
    *i; // no-warning
}

void simple_good_end_ptr_ptr(const std::vector<int> **v) {
  auto i = (*v)->end();
  if (i != (*v)->end())
    *i; // no-warning
}

void simple_good_end_ptr_ptr_ref(const std::vector<int> **&v) {
  auto i = (*v)->end();
  if (i != (*v)->end())
    *i; // no-warning
}

void simple_good_end_ptr_ptr_rref(const std::vector<int> **&&v) {
  auto i = (*v)->end();
  if (i != (*v)->end())
    *i; // no-warning
}

void simple_good_end_negated(const std::vector<int> &v) {
  auto i = v.end();
  if (!(i == v.end()))
    *i; // no-warning
}

void simple_bad_end(const std::vector<int> &v) {
  auto i = v.end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void simple_bad_end_ptr(const std::vector<int> *v) {
  auto i = v->end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void simple_bad_end_ptr_ref(const std::vector<int> *&v) {
  auto i = v->end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void simple_bad_end_ptr_rref(const std::vector<int> *&&v) {
  auto i = v->end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void simple_bad_end_ptr_ptr(const std::vector<int> **v) {
  auto i = (*v)->end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void simple_bad_end_ptr_ptr_ref(const std::vector<int> **&v) {
  auto i = (*v)->end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void simple_bad_end_ptr_ptr_rref(const std::vector<int> **&&v) {
  auto i = (*v)->end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void simple_good_begin(const std::vector<int> &v) {
  auto i = v.begin();
  if (i != v.begin())
    *--i; // no-warning
}

void simple_good_begin_negated(const std::vector<int> &v) {
  auto i = v.begin();
  if (!(i == v.begin()))
    *--i; // no-warning
}

void simple_bad_begin(const std::vector<int> &v) {
  auto i = v.begin(); // expected-note{{Iterator reached the first position of the container}}
  *--i; // expected-warning{{Iterator decremented ahead of its valid range}}
        // expected-note@-1{{Iterator decremented ahead of its valid range}}
}

void decr_begin(const std::vector<int> &v) {
  auto i = v.begin(); // expected-note{{Iterator reached the first position of the container}}
  --i; // expected-warning{{Iterator decremented ahead of its valid range}}
       // expected-note@-1{{Iterator decremented ahead of its valid range}}
}

void incr_end(const std::vector<int> &v) {
  auto i = v.end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  ++i; // expected-warning{{Iterator incremented behind the past-the-end iterator}}
       // expected-note@-1{{Iterator incremented behind the past-the-end iterator}}
}

void copy(const std::vector<int> &v) {
  auto i1 = v.end();
  auto i2 = i1; // expected-note{{Iterator reached the past-the-end position of the container}}
  *i2; // expected-warning{{Past-the-end iterator dereferenced}}
       // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void decrease(const std::vector<int> &v) {
  auto i = v.end();
  --i;
  *i; // no-warning
}

void copy_and_decrease1(const std::vector<int> &v) {
  auto i1 = v.end();
  auto i2 = i1;
  --i1;
  *i1; // no-warning
}

void copy_and_decrease2(const std::vector<int> &v) {
  auto i1 = v.end();
  auto i2 = i1; // expected-note{{Iterator reached the past-the-end position of the container}}
  --i1;
  *i2; // expected-warning{{Past-the-end iterator dereferenced}}
       // expected-note@-1{{Past-the-end iterator dereferenced}}
}


void copy_and_increase1(const std::vector<int> &v) {
  auto i1 = v.begin();
  auto i2 = i1;
  ++i1;
  if (i1 == v.end())
    *i2; // no-warning
}

void copy_and_increase2(const std::vector<int> &v) {
  auto i1 = v.begin();
  auto i2 = i1;
  ++i1;
  if (i2 == v.end()) // expected-note 0-1{{Assuming the condition is true}}
                     // expected-note@-1{{Assuming the container/range is empty}}
                     // expected-note@-2{{Taking true branch}}
    *i2; // expected-warning{{Past-the-end iterator dereferenced}}
         // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_find(std::vector<int> &V, int e) {
  auto first = std::find(V.begin(), V.end(), e);
  if (V.end() != first)
    *first; // no-warning
}

void bad_find(std::vector<int> &V, int e) {
  auto first = std::find(V.begin(), V.end(), e); // expected-note{{Iterator reached the past-the-end position of the container}}
  *first; // expected-warning{{Past-the-end iterator dereferenced}}
          // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_find_end(std::vector<int> &V, std::vector<int> &seq) {
  auto last = std::find_end(V.begin(), V.end(), seq.begin(), seq.end());
  if (V.end() != last)
    *last; // no-warning
}

void bad_find_end(std::vector<int> &V, std::vector<int> &seq) {
  auto last = std::find_end(V.begin(), V.end(), seq.begin(), seq.end()); // expected-note{{Iterator reached the past-the-end position of the container}}
  *last; // expected-warning{{Past-the-end iterator dereferenced}}
         // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_find_first_of(std::vector<int> &V, std::vector<int> &seq) {
  auto first =
      std::find_first_of(V.begin(), V.end(), seq.begin(), seq.end());
  if (V.end() != first)
    *first; // no-warning
}

void bad_find_first_of(std::vector<int> &V, std::vector<int> &seq) {
  auto first = std::find_end(V.begin(), V.end(), seq.begin(), seq.end()); // expected-note{{Iterator reached the past-the-end position of the container}}
  *first; // expected-warning{{Past-the-end iterator dereferenced}}
          // expected-note@-1{{Past-the-end iterator dereferenced}}
}

bool odd(int i) { return i % 2; }

void good_find_if(std::vector<int> &V) {
  auto first = std::find_if(V.begin(), V.end(), odd);
  if (V.end() != first)
    *first; // no-warning
}

void bad_find_if(std::vector<int> &V, int e) {
  auto first = std::find_if(V.begin(), V.end(), odd); // expected-note{{Iterator reached the past-the-end position of the container}}
  *first; // expected-warning{{Past-the-end iterator dereferenced}}
          // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_find_if_not(std::vector<int> &V) {
  auto first = std::find_if_not(V.begin(), V.end(), odd);
  if (V.end() != first)
    *first; // no-warning
}

void bad_find_if_not(std::vector<int> &V, int e) {
  auto first = std::find_if_not(V.begin(), V.end(), odd); // expected-note{{Iterator reached the past-the-end position of the container}}
  *first; // expected-warning{{Past-the-end iterator dereferenced}}
          // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_lower_bound(std::vector<int> &V, int e) {
  auto first = std::lower_bound(V.begin(), V.end(), e);
  if (V.end() != first)
    *first; // no-warning
}

void bad_lower_bound(std::vector<int> &V, int e) {
  auto first = std::lower_bound(V.begin(), V.end(), e); // expected-note{{Iterator reached the past-the-end position of the container}}
  *first; // expected-warning{{Past-the-end iterator dereferenced}}
          // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_upper_bound(std::vector<int> &V, int e) {
  auto last = std::lower_bound(V.begin(), V.end(), e);
  if (V.end() != last)
    *last; // no-warning
}

void bad_upper_bound(std::vector<int> &V, int e) {
  auto last = std::lower_bound(V.begin(), V.end(), e); // expected-note{{Iterator reached the past-the-end position of the container}}
  *last; // expected-warning{{Past-the-end iterator dereferenced}}
         // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_search(std::vector<int> &V, std::vector<int> &seq) {
  auto first = std::search(V.begin(), V.end(), seq.begin(), seq.end());
  if (V.end() != first)
    *first; // no-warning
}

void bad_search(std::vector<int> &V, std::vector<int> &seq) {
  auto first = std::search(V.begin(), V.end(), seq.begin(), seq.end()); // expected-note{{Iterator reached the past-the-end position of the container}}
  *first; // expected-warning{{Past-the-end iterator dereferenced}}
          // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_search_n(std::vector<int> &V, std::vector<int> &seq) {
  auto nth = std::search_n(V.begin(), V.end(), seq.begin(), seq.end());
  if (V.end() != nth)
    *nth; // no-warning
}

void bad_search_n(std::vector<int> &V, std::vector<int> &seq) {
  auto nth = std::search_n(V.begin(), V.end(), seq.begin(), seq.end()); // expected-note{{Iterator reached the past-the-end position of the container}}
  *nth; // expected-warning{{Past-the-end iterator dereferenced}}
        // expected-note@-1{{Past-the-end iterator dereferenced}}
}

template <class InputIterator, class T>
InputIterator nonStdFind(InputIterator first, InputIterator last,
                         const T &val) {
  for (auto i = first; i != last; ++i) {
    if (*i == val) {
      return i;
    }
  }
  return last;
}

void good_non_std_find(std::vector<int> &V, int e) {
  auto first = nonStdFind(V.begin(), V.end(), e);
  if (V.end() != first)
    *first; // no-warning
}

void bad_non_std_find(std::vector<int> &V, int e) {
  auto first = nonStdFind(V.begin(), V.end(), e); // expected-note{{Calling 'nonStdFind<__vector_iterator<int, int *, int &>, int>'}}
                                                  // expected-note@-16{{Assuming the container/range is empty}}
                                                  // expected-note@-17{{Loop condition is false. Execution continues on line}}
                                                  // expected-note@-13{{Iterator reached the past-the-end position of the container}}
                                                  // expected-note@-4{{Returning from 'nonStdFind<__vector_iterator<int, int *, int &>, int>'}}
  *first; // expected-warning{{Past-the-end iterator dereferenced}}
          // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void tricky(std::vector<int> &V, int e) {
  const auto first = V.begin();
  const auto comp1 = (first != V.end()), comp2 = (first == V.end());
  if (comp1)
    *first;
}

void loop(std::vector<int> &V, int e) {
  auto start = V.begin();
  while (true) {
    auto item = std::find(start, V.end(), e);
    if (item == V.end())
      break;
    *item;          // no-warning
    start = ++item; // no-warning
  }
}

void good_overwrite(std::vector<int> &vec) {
  auto i = vec.end();
  i = vec.begin();
  *i; // no-warning
}

void good_overwrite_find(std::vector<int> &vec, int e) {
  auto i = std::find(vec.begin(), vec.end(), e);
  if(i == vec.end()) {
    i = vec.begin();
  }
  *i; // no-warning
}

void bad_overwrite(std::vector<int> &vec) {
  auto i = vec.begin();
  i = vec.end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void bad_overwrite_find(std::vector<int> &vec, int e) {
  auto i = std::find(vec.begin(), vec.end(), e); // expected-note{{Iterator reached the past-the-end position of the container}}
  if(i != vec.end()) { // expected-note{{Taking false branch}}
    i = vec.begin();
  }
  *i; // expected-warning{{Past-the-end iterator dereferenced}}
      // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void good_advance(std::vector<int> &vec) {
  auto i = vec.end();
  std::advance(i, -1);
  *i; // no-warning
}

void good_prev(std::vector<int> &vec) {
  auto i = vec.end();
  *std::prev(i); // no-warning
}

void front(const std::vector<int> &vec) {
  vec.front(); // no-warning
}

void back(const std::vector<int> &vec) {
  vec.back(); // no-warning
}

void good_push_back(std::list<int> &L, int n) {
  auto i0 = --L.cend();
  L.push_back(n);
  *++i0; // no-warning
}

void bad_push_back(std::list<int> &L, int n) {
  auto i0 = --L.cend();
  L.push_back(n);
  ++i0;
  *++i0; // expected-warning{{Past-the-end iterator dereferenced}}
         // expected-note@-1{{Iterator reached the past-the-end position of the container}}
         // expected-note@-2{{Past-the-end iterator dereferenced}}
}

void good_pop_back(std::list<int> &L, int n) {
  auto i0 = --L.cend(); --i0;
  L.pop_back();
  *i0; // no-warning
}

void bad_pop_back(std::list<int> &L, int n) {
  auto i0 = --L.cend(); --i0;
  L.pop_back();
  *++i0; // expected-warning{{Past-the-end iterator dereferenced}}
         // expected-note@-1{{Iterator reached the past-the-end position of the container}}
         // expected-note@-2{{Past-the-end iterator dereferenced}}
}

void good_push_front(std::list<int> &L, int n) {
  auto i0 = L.cbegin();
  L.push_front(n);
  *--i0; // no-warning
}

void bad_push_front(std::list<int> &L, int n) {
  auto i0 = L.cbegin();
  L.push_front(n);
  --i0; // expected-note{{Iterator reached the first position of the container}}
  *--i0; // expected-warning{{Iterator decremented ahead of its valid range}}
         // expected-note@-1{{Iterator decremented ahead of its valid range}}
}

void good_pop_front(std::list<int> &L, int n) {
  auto i0 = ++L.cbegin();
  L.pop_front();
  *i0; // no-warning
}

void bad_pop_front(std::list<int> &L, int n) {
  auto i0 = ++L.cbegin();
  L.pop_front(); // expected-note{{Iterator reached the first position of the container}}
  *--i0; // expected-warning{{Iterator decremented ahead of its valid range}}
         // expected-note@-1{{Iterator decremented ahead of its valid range}}
}

void bad_move(std::list<int> &L1, std::list<int> &L2) {
  auto i0 = --L2.cend();
  L1 = std::move(L2);
  *++i0; // expected-warning{{Past-the-end iterator dereferenced}}
         // expected-note@-1{{Iterator reached the past-the-end position of the container}}
         // expected-note@-2{{Past-the-end iterator dereferenced}}
}

void bad_move_push_back(std::list<int> &L1, std::list<int> &L2, int n) {
  auto i0 = --L2.cend();
  L2.push_back(n);
  L1 = std::move(L2);
  ++i0;
  *++i0; // expected-warning{{Past-the-end iterator dereferenced}}
         // expected-note@-1{{Iterator reached the past-the-end position of the container}}
         // expected-note@-2{{Past-the-end iterator dereferenced}}
}

void good_decr_end(const std::list<int> &L) {
  auto i0 = L.end();
  --i0; // no-warning
}

void good_decr_end_advance(const std::list<int> &L) {
  auto i0 = L.end();
  std::advance(i0, -1); // no-warning
}

void good_decr_end_prev(const std::list<int> &L) {
  auto i0 = L.end();
  auto i1 = std::prev(i0); // no-warning
}

void bad_incr_end(const std::list<int> &L) {
  auto i0 = L.end(); // expected-note{{Iterator reached the past-the-end position of the container}}

  ++i0;  // expected-warning{{Iterator incremented behind the past-the-end iterator}}
         // expected-note@-1{{Iterator incremented behind the past-the-end iterator}}
}

void bad_decr_end_advance(const std::list<int> &L) {
  auto i0 = L.end(); // expected-note{{Iterator reached the past-the-end position of the container}}
  std::advance(i0, 1);  // expected-warning{{Iterator incremented behind the past-the-end }}
                        // expected-note@-1{{Iterator incremented behind the past-the-end iterator}}
}

void bad_decr_end_next(const std::list<int> &L) {
  auto i0 = L.end();
  auto i1 = std::next(i0);  // expected-warning{{Iterator incremented behind the past-the-end }}
                            // expected-note@-1{{Iterator reached the past-the-end position of the container}}
                            // expected-note@-2{{Iterator incremented behind the past-the-end iterator}}
}

void empty_range(const std::vector<int> &V) {
  if (V.begin() != V.end())
    return;

  int sum = 0;
  for (auto n : V) {
    sum += n;
  } // no-warning
}

void assert_find(const std::vector<int> &V, int e) {
  auto first = std::find(V.begin(), V.end(), e);
  assert(first != V.end() && "V should contain e in all cases");
  *first; // no-warning
}

void empty(const std::vector<int> &V) {
  for (auto n: V) {} // expected-note{{Assuming the container/range is empty}}
  *V.begin(); // expected-warning{{Past-the-end iterator dereferenced}}
              // expected-note@-1{{Past-the-end iterator dereferenced}}
}

void non_empty1(const std::vector<int> &V) {
  assert(!V.empty());
  for (auto n: V) {}
  *V.begin(); // no-warning
}

void non_empty2(const std::vector<int> &V) {
  for (auto n: V) {}
  assert(!V.empty());
  *V.begin(); // no-warning
}

struct Adapter {
  Adapter(std::vector<int>::iterator i): it(i) {}
  Adapter operator++() { ++it; return *this; }
private:
  std::vector<int>::iterator it;
};

void adapter_test(std::vector<int> &v) {
  Adapter ad(v.end()); // expected-note{{Calling constructor for 'Adapter'}}
                       // expected-note@-8{{Iterator reached the past-the-end position of the container}}
                       // expected-note@-2{{Returning from constructor for 'Adapter'}}
  ++ad; // expected-warning@-9{{Iterator incremented behind the past-the-end iterator}}
        // expected-note@-1{{Calling 'Adapter::operator++'}}
        // expected-note@-11{{Iterator incremented behind the past-the-end iterator}}
}

struct simple_iterator_base {
  simple_iterator_base();
  simple_iterator_base(const simple_iterator_base& rhs);
  simple_iterator_base &operator=(const simple_iterator_base& rhs);
  virtual ~simple_iterator_base();
  bool friend operator==(const simple_iterator_base &lhs,
                         const simple_iterator_base &rhs);
  bool friend operator!=(const simple_iterator_base &lhs,
                         const simple_iterator_base &rhs);
private:
  int *ptr;
};

struct simple_derived_iterator: public simple_iterator_base {
  int& operator*();
  int* operator->();
  simple_iterator_base &operator++();
  simple_iterator_base operator++(int);
  simple_iterator_base &operator--();
  simple_iterator_base operator--(int);
};

struct simple_container {
  typedef simple_derived_iterator iterator;

  iterator begin();
  iterator end();
};

void good_derived(simple_container c) {
  auto i0 = c.end();
  if (i0 != c.end()) {
    *i0; // no-warning
  }
}

void complex_increment(const std::vector<int> &V, unsigned n) {
  auto i = V.begin();
  i += n;
  if (i != V.end()) {
    *i; // no-warning
  }
}

bool is_empty_V() {
  std::vector<int> V;
  bool e = V.empty();
  return e;
}

void deferred_emptiness_check() {
  bool b = is_empty_V();
  if (b) {
  }
}

void push_back_to_default_constructed_vector(std::vector<int> &V) {
  assert(V.empty());
  V.push_back(0);

  auto i = V.begin();
  ++i;
  if (i != V.end())
    *i;
}

void iter_diff(std::vector<int> &V) {
  auto i0 = V.begin(), i1 = V.end();
  ptrdiff_t len = i1 - i0; // no-crash
}
