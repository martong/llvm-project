//===- Environment.h - Map from Stmt* to Locations/Values -------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defined the Environment and EnvironmentManager classes.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_STATICANALYZER_CORE_PATHSENSITIVE_ENVIRONMENT_H
#define LLVM_CLANG_STATICANALYZER_CORE_PATHSENSITIVE_ENVIRONMENT_H

#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/ADT/ImmutableMap.h"
#include <utility>

namespace clang {

class Stmt;

namespace ento {

class SValBuilder;
class SymbolReaper;

/// An entry in the environment consists of a Stmt and an LocationContext.
/// This allows the environment to manage context-sensitive bindings,
/// which is essentially for modeling recursive function analysis, among
/// other things.
class EnvironmentEntry : public std::pair<const Stmt *,
                                          const StackFrameContext *> {
public:
  EnvironmentEntry(const Stmt *s, const LocationContext *L);
  EnvironmentEntry()
      : std::pair<const Stmt *, const StackFrameContext *>(nullptr, nullptr) {}
  EnvironmentEntry(const Stmt *s, const StackFrameContext *L,
                   double) // TombStone
      : std::pair<const Stmt *, const StackFrameContext *>(s, L) {}

  const Stmt *getStmt() const { return first; }
  const LocationContext *getLocationContext() const { return second; }

  /// Profile an EnvironmentEntry for inclusion in a FoldingSet.
  static void Profile(llvm::FoldingSetNodeID &ID,
                      const EnvironmentEntry &E) {
    ID.AddPointer(E.getStmt());
    ID.AddPointer(E.getLocationContext());
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    Profile(ID, *this);
  }
};

} // namespace ento
} // namespace clang

namespace llvm {
template <> struct DenseMapInfo<clang::ento::EnvironmentEntry> {
  static clang::ento::EnvironmentEntry getEmptyKey() {
    return clang::ento::EnvironmentEntry();
  }

  static clang::ento::EnvironmentEntry getTombstoneKey() {
    return clang::ento::EnvironmentEntry(
        DenseMapInfo<clang::Stmt *>::getTombstoneKey(),
        DenseMapInfo<clang::StackFrameContext *>::getTombstoneKey(), 3.14);
  }

  static unsigned getHashValue(const clang::ento::EnvironmentEntry &Val) {
    return DenseMapInfo<clang::Stmt *>::getHashValue(Val.getStmt()) ^
           DenseMapInfo<clang::LocationContext *>::getHashValue(
               Val.getLocationContext());
  }

  static bool isEqual(const clang::ento::EnvironmentEntry &LHS,
                      const clang::ento::EnvironmentEntry &RHS) {
    return LHS == RHS;
  }
};
} // namespace llvm

namespace clang {
namespace ento {

/// An immutable map from EnvironemntEntries to SVals.
class Environment {
private:
  friend class EnvironmentManager;

  using BindingsTy = llvm::DenseMap<EnvironmentEntry, SVal>;

  BindingsTy ExprBindings;

  Environment(BindingsTy eb) : ExprBindings(eb) {}

  SVal lookupExpr(const EnvironmentEntry &E) const;

public:
  using iterator = BindingsTy::iterator;
  using const_iterator = BindingsTy::const_iterator;

  const_iterator begin() const { return ExprBindings.begin(); }
  const_iterator end() const { return ExprBindings.end(); }

  /// Fetches the current binding of the expression in the
  /// Environment.
  SVal getSVal(const EnvironmentEntry &E, SValBuilder &svalBuilder) const;

  /// Profile - Profile the contents of an Environment object for use
  ///  in a FoldingSet.
  static void Profile(llvm::FoldingSetNodeID& ID, const Environment* env) {
    ID.AddPointer(&env->ExprBindings);
  }

  /// Profile - Used to profile the contents of this object for inclusion
  ///  in a FoldingSet.
  void Profile(llvm::FoldingSetNodeID& ID) const {
    Profile(ID, this);
  }

  bool operator==(const Environment& RHS) const {
    return ExprBindings == RHS.ExprBindings;
  }

  void printJson(raw_ostream &Out, const ASTContext &Ctx,
                 const LocationContext *LCtx = nullptr, const char *NL = "\n",
                 unsigned int Space = 0, bool IsDot = false) const;
};

class EnvironmentManager {
private:
  struct FactoryTy {
    Environment getEmptyMap() { return Environment(Environment::BindingsTy()); }
    Environment remove(const Environment::BindingsTy &EB,
                       const EnvironmentEntry &E) {
      Environment::BindingsTy Copy(EB);
      Copy.erase(E);
      return Copy;
    }
    Environment add(const Environment::BindingsTy &EB,
                    const EnvironmentEntry &E, SVal V) {
      Environment::BindingsTy Copy(EB);
      Copy.insert({E, V});
      return Copy;
    }
  };

  FactoryTy F;

public:
  EnvironmentManager(llvm::BumpPtrAllocator &) : F() {}

  Environment getInitialEnvironment() {
    return Environment(F.getEmptyMap());
  }

  /// Bind a symbolic value to the given environment entry.
  Environment bindExpr(Environment Env, const EnvironmentEntry &E, SVal V,
                       bool Invalidate);

  Environment removeDeadBindings(Environment Env,
                                 SymbolReaper &SymReaper,
                                 ProgramStateRef state);
};

} // namespace ento

} // namespace clang

#endif // LLVM_CLANG_STATICANALYZER_CORE_PATHSENSITIVE_ENVIRONMENT_H
