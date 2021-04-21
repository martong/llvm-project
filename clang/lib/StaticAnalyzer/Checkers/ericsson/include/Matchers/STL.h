#ifndef __MATCHERS_STL_H__
#define __MATCHERS_STL_H__

#include <set>
#include <string>

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"

namespace stl {
inline std::set<std::string> getAssociativeContainerNames() {
  return {"std::map", "std::multimap", "std::unordered_map",
          "std::unordered_multimap"};
}

inline bool isContainer(const std::string &className) {
  static const std::set<std::string> containerNames{"std::vector",
                                                    "std::list",
                                                    "std::array",
                                                    "std::deque",
                                                    "std::forward_list",
                                                    "std::set",
                                                    "std::map",
                                                    "std::multiset",
                                                    "std::multimap",
                                                    "std::unordered_set",
                                                    "std::unordered_map",
                                                    "std::unordered_multiset",
                                                    "std::unordered_multimap",
                                                    "std::stack",
                                                    "std::queue",
                                                    "std::priority_queue"};
  return containerNames.find(className) != containerNames.end();
}

inline bool isAssociativeContainer(const std::string &className) {
  static const std::set<std::string> names = getAssociativeContainerNames();
  return names.find(className) != names.end();
}

inline bool isShrinkableContainer(const std::string &className) {
  static const std::set<std::string> names{"std::deque", "std::basic_string",
                                           "std::vector"};
  return names.find(className) != names.end();
}

inline bool isSyncType(const std::string &className) {
  static const std::set<std::string> names = {
      "std::mutex",           "std::timed_mutex",
      "std::recursive_mutex", "std::recursive_timed_mutex",
      "std::lock_guard",      "std::unique_lock"};
  return names.find(className) != names.end();
}

unsigned getItemTemplateArg(const std::string &containerName);

} // end namespace stl

namespace clang {
namespace ast_matchers {

AST_MATCHER(NamedDecl, stlContainer) {
  return stl::isContainer(Node.getQualifiedNameAsString());
}

AST_MATCHER(NamedDecl, stlShrinkableContainer) {
  return stl::isShrinkableContainer(Node.getQualifiedNameAsString());
}

AST_MATCHER_P(ClassTemplateSpecializationDecl, stlContainerItem,
              internal::Matcher<TemplateArgument>, InnerMatcher) {
  return InnerMatcher.matches(
      Node.getTemplateArgs().get(
          stl::getItemTemplateArg(Node.getNameAsString())),
      Finder, Builder);
}

AST_MATCHER(NamedDecl, stlSyncType) {
  return stl::isSyncType(Node.getQualifiedNameAsString());
}

} // namespace ast_matchers
} // namespace clang

#endif // __MATCHERS_STL_H__
