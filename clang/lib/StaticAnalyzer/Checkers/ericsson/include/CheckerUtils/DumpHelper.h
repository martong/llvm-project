#ifndef __DUMP_HELPER_H__
#define __DUMP_HELPER_H__

#include <functional>
#include <ostream>

namespace clang {
namespace ento {
namespace ericsson {

class DumpHelper {
public:
  static DumpHelper write(const std::string &str) {
    return DumpHelper([=](std::ostream &os) { os << str; });
  }

  explicit DumpHelper(std::function<void(std::ostream &)> dumper_)
      : m_dumper(dumper_) {}

private:
  std::function<void(std::ostream &)> m_dumper;

  friend std::ostream &operator<<(std::ostream &os, const DumpHelper &obj);
};

inline std::ostream &operator<<(std::ostream &os, const DumpHelper &obj) {
  os << std::flush;
  obj.m_dumper(os);
  os << std::flush;
  return os;
}

template <typename T> DumpHelper dumpVal(const T &val) {
  return DumpHelper([=](std::ostream &os) { val.dump(); });
}

template <typename T> DumpHelper dumpPtr(const T *ptr) {
  if (!ptr) {
    return DumpHelper::write("(nullptr)");
  } else {
    // unfortunately, we cannot just do return dumpVal(*ptr), because that will
    // screw up pure virtual object instances
    return DumpHelper([=](std::ostream &os) { ptr->dump(); });
  }
}

// -- specializations --
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"

inline DumpHelper dump(const clang::ento::ConditionTruthVal &v) {
  if (v.isConstrainedTrue()) {
    return DumpHelper::write("ConditionTruthVal{constrained true}");
  } else if (v.isConstrainedFalse()) {
    return DumpHelper::write("ConditionTruthVal{constrained false}");
  } else {
    return DumpHelper::write("ConditionTruthVal{underconstrained}");
  }
}

template <typename T> DumpHelper dump(const T *ptr) { return dumpPtr(ptr); }

template <typename T> DumpHelper dump(const T &v) { return dumpVal(v); }

} // namespace ericsson
} // namespace ento
} // namespace clang

#endif // __DUMP_HELPER_H__
