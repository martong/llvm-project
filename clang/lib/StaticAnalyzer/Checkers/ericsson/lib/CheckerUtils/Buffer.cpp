#include <iostream>

#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "CheckerUtils/Buffer.h"

namespace clang {
namespace ento {
namespace ericsson {

namespace Buffer {

const char *skipIgnoredCode(const char *buffer, bool *o_skippedNewLine,
                            unsigned *o_newLineIdent) {
  if (!buffer)
    return nullptr;

  if (o_skippedNewLine) {
    *o_skippedNewLine = false;
  }

  bool isMultilineComment = false;
  bool isLineComment = false;

  for (char c = buffer[0]; c; c = *(++buffer)) {
    if (c == '/' && *(buffer + 1) == '*' && !isLineComment) {
      isMultilineComment = true;
      buffer++;
    } else if (c == '*' && *(buffer + 1) == '/' && !isLineComment) {
      isMultilineComment = false;
      buffer++;
    } else if (c == '/' && *(buffer + 1) == '/' && !isMultilineComment) {
      isLineComment = true;
      buffer++;
    } else if (c == '\n' || c == '\r') {
      isLineComment = false;

      if (o_skippedNewLine) {
        *o_skippedNewLine = true;
      }

      if (o_newLineIdent) {
        *o_newLineIdent = 0;
      }
    } else if (c == ' ' || c == '\t') {
      // ignore whitespaces, but count the identation
      if (o_newLineIdent && !isMultilineComment) {
        // if (c == '\t')
        //(*o_newLineIdent)++;
        (*o_newLineIdent)++; // TODO: tabs count as one identation?
      }
      continue;
    } else if (isLineComment || isMultilineComment) {
      // ignore comments
      continue;
    } else {
      // not in a comment, not a whitespace: return
      return buffer;
    }
  }

  return nullptr;
}

const char *skipBracket(const char *buffer) {
  // don't count when it is in a string or character literal
  unsigned brackets = 0;
  bool prevIsBackSlash = false, isInCharLit = false, isInStringLit = false;
  for (char c = buffer[0]; c; c = *(++buffer)) {
    if (c == '\\' && !prevIsBackSlash) {
      prevIsBackSlash = true;
    } else {
      if (c == '\'' && !prevIsBackSlash && !isInStringLit) {
        isInCharLit = !isInCharLit;
      } else if (c == '\"' && !prevIsBackSlash && !isInCharLit) {
        isInStringLit = !isInStringLit;
      } else if (c == '(' && !isInStringLit && !isInCharLit) {
        brackets++;
      } else if (c == ')' && !isInStringLit && !isInCharLit) {
        if (--brackets == 0)
          return ++buffer;
      }
      prevIsBackSlash = false;
    }
  }
  return nullptr;
}

// TODO: The following codes should return StringRef and the client should
// decide whether the content of the buffer should be copied or not.
std::string getSourceCode(const Stmt *stmt, const SourceManager &sourceMgr,
                          const LangOptions &langOpts) {
  SourceLocation locStart = sourceMgr.getExpansionLoc(stmt->getBeginLoc());
  SourceLocation locEnd = sourceMgr.getExpansionLoc(stmt->getEndLoc());

  return std::string(
      sourceMgr.getCharacterData(locStart),
      sourceMgr.getFileOffset(locEnd) +
          Lexer::MeasureTokenLength(locEnd, sourceMgr, langOpts) -
          sourceMgr.getFileOffset(locStart));
}

std::string getSourceCode(const Stmt *stmt, ento::CheckerContext &context) {
  return getSourceCode(stmt, context.getSourceManager(), context.getLangOpts());
}

std::string getSourceCodeLine(const Stmt *stmt, const SourceManager &sourceMgr,
                              bool skipIndentation) {
  SourceLocation locStart = stmt->getBeginLoc();

  SourceLocation lineBegin = sourceMgr.translateFileLineCol(
      sourceMgr.getFileEntryForID(sourceMgr.getFileID(locStart)),
      sourceMgr.getSpellingLineNumber(locStart), 1);

  const char *buffer = sourceMgr.getCharacterData(lineBegin);
  unsigned startPos = 0;
  unsigned lineLength = 0;

  for (const char *p = buffer; *p != '\n' && *p != '\r' && *p; ++p) {
    if (skipIndentation && lineLength == 0 && (*p == ' ' || *p == '\t')) {
      startPos++;
    } else {
      lineLength++;
    }
  }
  return std::string(buffer + startPos, lineLength);
}

std::string getSourceCodeLine(const Stmt *stmt, ento::CheckerContext &context,
                              bool skipIndentation) {
  return getSourceCodeLine(stmt, context.getSourceManager(), skipIndentation);
}
} // namespace Buffer

} // namespace ericsson
} // namespace ento
} // namespace clang
