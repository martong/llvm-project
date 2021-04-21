// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.precpp11.stl.AllocWithState -Wno-everything -verify %s

#include "Inputs/system-header-simulator-cxx.h"
#include "Inputs/system-header-simulator-cxx-string.h"

// Note: there is no need to provide an implementation! We don't need it to build a correct AST. (Linking this file would definitely fail though.)
template <typename T>
struct MyAlloc
{
    typedef std::size_t    size_type;
    typedef std::ptrdiff_t difference_type;
    typedef T*             pointer;
    typedef const T*       const_pointer;
    typedef T&             reference;
    typedef const T&       const_reference;
    typedef T              value_type;

    int m_state = 10;

    T* allocate(std::size_t num, const void* hint = 0);
    void deallocate(T* p, std::size_t num);

    T* address(T& value) const;
    const T* address(const T& value) const;

    std::size_t max_size() const noexcept;
    void construct(T* p, const T& value);
    void destroy(T* p);

    // rebind allocator to type U
    template <typename U>
    struct rebind {
        typedef MyAlloc<U> other;
    };
};

// C+11 "template typedef"
template <typename T>
using MyIntVec = std::vector<T, MyAlloc<T>>;

int main()
{
    // The type of this variable is defined by a template "using" structure.
    // That is a C++11 feature. In C++11 this checker is not valid, so it
    // doesn't matter if this case is not found by the checker.
    // TODO: However there is some reason why this finding disappeared, because
    // this case was found by clang5. It would be nice to see what changed.
    MyIntVec<int> v;
    std::vector<int, MyAlloc<int>> v2;// expected-warning {{This variable uses the type 'MyAlloc' as allocator, which contains state (e.g. field 'm_state'). Allocator classes should be stateless}}
    std::map<int, float, std::less<int>, MyAlloc<std::pair<const int, float>>> m;// expected-warning {{This variable uses the type 'MyAlloc' as allocator, which contains state (e.g. field 'm_state'). Allocator classes should be stateless}}
    std::basic_string<char, std::char_traits<char>, MyAlloc<char>> s;// expected-warning {{This variable uses the type 'MyAlloc' as allocator, which contains state (e.g. field 'm_state'). Allocator classes should be stateless}}

    typedef std::basic_string<char, std::char_traits<char>, MyAlloc<char>> MyString;
    typedef std::map<MyString, MyString, std::less<MyString>, MyAlloc<std::pair<const MyString, MyString>>> MyMap;
    MyMap m2;

    // control
    std::vector<int> v3;
    std::string s2;

    return 0;
}
