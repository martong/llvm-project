#ifndef __BUFFER_HELPER_H__
#define __BUFFER_HELPER_H__

#include <string>

#include "clang/Basic/SourceManager.h"

namespace clang {
class Stmt;
class LangOptions;
namespace ento {
class CheckerContext;
}
} // namespace clang

namespace clang {
namespace ento {
namespace ericsson {

// A static class containing utility functions for using the source code buffer.
namespace Buffer {

// Skips all whitespace characters and comments. Returns nullptr if encounters a
// NULL
// ('\0') character.
const char *skipIgnoredCode(const char *buffer,
                            bool *o_skippedNewLine = nullptr,
                            unsigned *o_newLineIdent = nullptr);

// Starts reading from the given buffer position, until it encounters an opening
// bracket
// '(', and then reads past the closing pair ')'.
const char *skipBracket(const char *buffer);

// Gets the source code represented by the the given statement.
std::string getSourceCode(const clang::Stmt *stmt,
                          const clang::SourceManager &sourceMgr,
                          const clang::LangOptions &langOpts);
std::string getSourceCode(const clang::Stmt *stmt,
                          clang::ento::CheckerContext &context);

// Gets the source code line containing the given statement.
std::string getSourceCodeLine(const clang::Stmt *stmt,
                              const clang::SourceManager &sourceMgr,
                              bool skipIndentation = true);
std::string getSourceCodeLine(const clang::Stmt *stmt,
                              clang::ento::CheckerContext &context,
                              bool skipIndentation = true);
} // namespace Buffer

} // namespace ericsson
} // namespace ento
} // namespace clang

#endif // __BUFFER_HELPER_H__
