// Like the compiler, the static analyzer treats some functions differently if
// they come from a system header -- for example, it is assumed that system
// functions do not arbitrarily free() their parameters, and that some bugs
// found in system headers cannot be fixed by the user and should be
// suppressed.
#pragma clang system_header


namespace std 
{
class string {
 public:
  ~string();
  char &operator[](size_t pos);
  const char &operator[](size_t pos) const;
  const char *c_str();
  size_t length() const;
  size_t find(char ch, size_t pos = 0) const;
};

template <typename T, class TRAITS, class ALLOCA>
class basic_string{
	ALLOCA allocator;
};
}
