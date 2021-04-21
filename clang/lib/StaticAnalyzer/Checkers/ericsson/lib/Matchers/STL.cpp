#include "Matchers/STL.h"

using namespace clang;
using namespace ast_matchers;

unsigned stl::getItemTemplateArg(const std::string &containerName) {
  static const std::set<std::string> assocContainers =
      getAssociativeContainerNames();
  if (assocContainers.find(containerName) != assocContainers.end()) {
    return 1;
  }
  return 0;
}
