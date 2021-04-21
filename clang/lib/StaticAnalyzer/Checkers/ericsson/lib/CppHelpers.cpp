#include "CppHelpers.h"

namespace clang {
namespace ento {
namespace ericsson {

bool isLower(char c) { return 'a' <= c && c <= 'z'; }

bool isUpper(char c) { return 'A' <= c && c <= 'Z'; }

char toLower(char c) { return 'a' + (c - 'A'); }

char toUpper(char c) { return 'A' + (c - 'a'); }

std::string str_replace(std::string where, const std::string &what,
                        const std::string &with) {
  auto loc = where.find(what);
  if (loc == std::string::npos) {
    return where;
  }

  return where.replace(loc, what.size(), with);
}

// Original source: http://stackoverflow.com/a/236803/128240
std::vector<std::string> &str_split(const std::string &s, char delim,
                                    std::vector<std::string> *elems) {
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    elems->push_back(item);
  }
  return *elems;
}

std::vector<std::string> str_split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  str_split(s, delim, &elems);
  return elems;
}

} // namespace clang
} // namespace ento
} // namespace ericsson
