#ifndef __CPP_HELPERS__
#define __CPP_HELPERS__

#include <sstream>
#include <string>
#include <vector>

namespace clang {
namespace ento {
namespace ericsson {

bool isLower(char c);

bool isUpper(char c);

char toLower(char c);

char toUpper(char c);

std::string str_replace(std::string where, const std::string &what,
                        const std::string &with);

// Original source: http://stackoverflow.com/a/236803/128240
std::vector<std::string> &str_split(const std::string &s, char delim,
                                    std::vector<std::string> *elems);

std::vector<std::string> str_split(const std::string &s, char delim);

} // namespace ericsson
} // namespace ento
} // namespace clang

#endif // __CPP_HELPERS__
