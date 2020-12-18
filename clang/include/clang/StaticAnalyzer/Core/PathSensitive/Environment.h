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

/// An immutable map from EnvironemntEntries to SVals.
class Environment {
private:
  friend class EnvironmentManager;

  using BindingsTy = std::vector<std::pair<EnvironmentEntry, SVal>>;

  BindingsTy* ExprBindings = nullptr;
  int Offset = -1;

  Environment(BindingsTy* eb, int Offset) : ExprBindings(eb), Offset(Offset) {}

  SVal lookupExpr(const EnvironmentEntry &E) const;

public:
  using iterator = BindingsTy::iterator;
  using const_iterator = BindingsTy::const_iterator;

  const_iterator begin() const { return ExprBindings->begin(); }
  const_iterator end() const { return ExprBindings->begin() + Offset; }

  /// Fetches the current binding of the expression in the
  /// Environment.
  SVal getSVal(const EnvironmentEntry &E, SValBuilder &svalBuilder) const;

  /// Profile - Profile the contents of an Environment object for use
  ///  in a FoldingSet.
  static void Profile(llvm::FoldingSetNodeID& ID, const Environment* env) {
    //env->ExprBindings.Profile(ID);
    ID.AddPointer(&env->ExprBindings);
    ID.AddInteger(env->Offset);
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
  std::vector<std::unique_ptr<Environment::BindingsTy>> Bindings;
  llvm::DenseSet<std::pair<Environment::BindingsTy*, int>> Refs;
  Environment getEmptyMap() {
    Bindings.emplace_back(std::make_unique<Environment::BindingsTy>());
    auto E = Environment(Bindings.back().get(), 0);
    //Refs.insert({Bindings.back().get(), 0});
    return E;
  }
  Environment add(Environment Env,
                  const EnvironmentEntry &E, SVal V) {

    auto NewEnv = Environment(Env.ExprBindings, Env.Offset+1);
    // Check for existing node
    //if (Refs.count({NewEnv.ExprBindings, NewEnv.Offset})) { // count(NewEnv)
      //Bindings.emplace_back(std::make_unique<Environment::BindingsTy>(Env.begin(), Env.end()));
      //NewEnv = Environment(Bindings.back().get(), NewEnv.Offset);
    //}

    //Refs.insert({NewEnv.ExprBindings, NewEnv.Offset}); // insert(NewEnv)
    NewEnv.ExprBindings->emplace_back(E, V);
    return NewEnv;
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
