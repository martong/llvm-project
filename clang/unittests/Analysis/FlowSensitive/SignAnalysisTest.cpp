//===- unittests/Analysis/FlowSensitive/MultiVarConstantPropagation.cpp --===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defines a simplistic version of Constant Propagation as an example
//  of a forward, monotonic dataflow analysis. The analysis tracks all
//  variables in the scope, but lacks escape analysis.
//
//===----------------------------------------------------------------------===//

#include "TestingSupport.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Analysis/FlowSensitive/DataflowAnalysis.h"
#include "clang/Analysis/FlowSensitive/DataflowEnvironment.h"
#include "clang/Analysis/FlowSensitive/DataflowLattice.h"
#include "clang/Analysis/FlowSensitive/MapLattice.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/None.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/Error.h"
#include "llvm/Testing/Support/Annotations.h"
#include "llvm/Testing/Support/Error.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

namespace clang {
namespace dataflow {
namespace {
using namespace ast_matchers;

// Models the signedness of a variable, for all paths through
// the program.
struct SignLattice {
  enum class SignState : int {
    Bottom,
    Negative,
    Zero,
    Positive,
    Top,
  };
  SignState State;

  constexpr SignLattice() : State(SignState::Bottom){}
  constexpr SignLattice(int64_t V)
      : State(V == 0 ? SignState::Zero
                     : (V < 0 ? SignState::Negative : SignState::Positive)) {}
  constexpr SignLattice(SignState S) : State(S){}

  static constexpr SignLattice bottom() {
    return SignLattice(SignState::Bottom);
  }
  static constexpr SignLattice negative() {
    return SignLattice(SignState::Negative);
  }
  static constexpr SignLattice zero() {
    return SignLattice(SignState::Zero);
  }
  static constexpr SignLattice positive() {
    return SignLattice(SignState::Positive);
  }
  static constexpr SignLattice top() {
    return SignLattice(SignState::Top);
  }

  friend bool operator==(const SignLattice &Lhs, const SignLattice &Rhs) {
    return Lhs.State == Rhs.State;
  }
  friend bool operator!=(const SignLattice &Lhs, const SignLattice &Rhs) {
    return !(Lhs == Rhs);
  }

  LatticeJoinEffect join(const SignLattice &Other) {
    if (*this == Other || Other == bottom() || *this == top())
      return LatticeJoinEffect::Unchanged;

    if (*this == bottom()) {
      *this = Other;
      return LatticeJoinEffect::Changed;
    }

    *this = top();
    return LatticeJoinEffect::Changed;
  }
};

std::ostream &operator<<(std::ostream &OS, const SignLattice &L) {
  switch (L.State) {
  case SignLattice::SignState::Bottom:
    return OS << "Bottom";
  case SignLattice::SignState::Negative:
    return OS << "Negative";
  case SignLattice::SignState::Zero:
    return OS << "Zero";
  case SignLattice::SignState::Positive:
    return OS << "Positive";
  case SignLattice::SignState::Top:
    return OS << "Top";
  }
  llvm_unreachable("unknown SignState!");
}

using ConstantPropagationLattice = VarMapLattice<SignLattice>;

constexpr char kDecl[] = "decl";
constexpr char kVar[] = "var";
constexpr char kRHSVar[] = "rhsvar";
constexpr char kInit[] = "init";
constexpr char kJustAssignment[] = "just-assignment";
constexpr char kAssignment[] = "assignment";
constexpr char kComparison[] = "comparison";
constexpr char kRHS[] = "rhs";

auto refToVar(StringRef V) { return declRefExpr(to(varDecl().bind(V))); }

// N.B. This analysis is deliberately simplistic, leaving out many important
// details needed for a real analysis. Most notably, the transfer function does
// not account for the variable's address possibly escaping, which would
// invalidate the analysis. It also could be optimized to drop out-of-scope
// variables from the map.
class ConstantPropagationAnalysis
    : public DataflowAnalysis<ConstantPropagationAnalysis,
                              ConstantPropagationLattice> {
public:
  explicit ConstantPropagationAnalysis(ASTContext &Context)
      : DataflowAnalysis<ConstantPropagationAnalysis,
                         ConstantPropagationLattice>(Context) {}

  static ConstantPropagationLattice initialElement() {
    return ConstantPropagationLattice::bottom();
  }

  void branchTransfer(bool Branch, const Stmt *S,
                      ConstantPropagationLattice &Vars, Environment &Env) {
    auto matcher = binaryOperator(isComparisonOperator(),
                                  hasLHS(hasDescendant(refToVar(kVar))),
                                  hasRHS(expr().bind(kRHS)))
                       .bind(kComparison);
    ASTContext &Context = getASTContext();
    auto Results = match(matcher, *S, Context);
    if (Results.empty())
      return;
    const BoundNodes &Nodes = Results[0];

    const auto *Var = Nodes.getNodeAs<clang::VarDecl>(kVar);
    assert(Var != nullptr);
    if (const auto *BinOp =
            Nodes.getNodeAs<clang::BinaryOperator>(kComparison)) {
      const auto *RHS = Nodes.getNodeAs<clang::Expr>(kRHS);
      assert(RHS != nullptr);
      //BinOp->dump();
      //Env.dump();

      Expr::EvalResult R;
      if (!(RHS->EvaluateAsInt(R, Context) && R.Val.isInt()))
        return;
      auto V = SignLattice(R.Val.getInt().getExtValue());
      auto OpCode =
          Branch ? BinOp->getOpcode()
                 : BinaryOperator::negateComparisonOp(BinOp->getOpcode());
      switch (OpCode) {
      case BO_LT:
        if (V == SignLattice::positive()) {
          Vars[Var] = SignLattice::top();
        } else {
          // Var is less than 0 or a negative number.
          Vars[Var] = SignLattice::negative();
        }
        break;
      case BO_LE:
        // Var is less than or equal to a negative number.
        if (V == SignLattice::negative()) {
          Vars[Var] = SignLattice::negative();
        } else {
          // Var is less than or equal to 0 or a positive number.
          Vars[Var] = SignLattice::top();
        }
        break;
      case BO_GT:
        if (V == SignLattice::negative()) {
          Vars[Var] = SignLattice::top();
        } else {
          // Var is greater than 0 or a positive number.
          Vars[Var] = SignLattice::positive();
        }
        break;
      case BO_GE:
        // Var is greater than or equal to a positive number.
        if (V == SignLattice::positive()) {
          Vars[Var] = SignLattice::positive();
        } else {
          // Var is greater than or equal to 0 or a negative number.
          Vars[Var] = SignLattice::top();
        }
        break;
      case BO_EQ:
        Vars[Var] = V;
        break;
      default:
        ;
        //llvm_unreachable("not implemented");
      }
    }
  }

  void transfer(const Stmt *S, ConstantPropagationLattice &Vars,
                Environment &Env) {
    auto matcher = stmt(anyOf(
        declStmt(hasSingleDecl(
            varDecl(decl().bind(kVar), hasType(isInteger()),
                    optionally(hasInitializer(expr().bind(kInit))))
                .bind(kDecl))),
        binaryOperator(hasOperatorName("="), hasLHS(refToVar(kVar)),
          hasRHS(hasDescendant(refToVar(kRHSVar))))
            .bind(kJustAssignment),
        binaryOperator(isAssignmentOperator(), hasLHS(refToVar(kVar)))
            .bind(kAssignment)
        ));

    ASTContext &Context = getASTContext();
    auto Results = match(matcher, *S, Context);
    if (Results.empty())
      return;
    const BoundNodes &Nodes = Results[0];

    const auto *Var = Nodes.getNodeAs<clang::VarDecl>(kVar);
    assert(Var != nullptr);

    if (Nodes.getNodeAs<clang::VarDecl>(kDecl) != nullptr) {
      if (const auto *E = Nodes.getNodeAs<clang::Expr>(kInit)) {
        Expr::EvalResult R;
        Vars[Var] = (E->EvaluateAsInt(R, Context) && R.Val.isInt())
                        ? SignLattice(R.Val.getInt().getExtValue())
                        : SignLattice::bottom();
      } else {
        // An unitialized variable holds *some* value, but we don't know what it
        // is (it is implementation defined), so we set it to top.
        Vars[Var] = SignLattice::top();
      }
    // Assign one variable to another.
    } else if (auto *A = Nodes.getNodeAs<clang::Expr>(kJustAssignment)) {
      const auto *RHSVar = Nodes.getNodeAs<clang::VarDecl>(kRHSVar);
      assert(RHSVar);
      auto It = Vars.find(RHSVar);
      if (It != Vars.end())
        Vars[Var] = It->second;
      else
        Vars[Var] = SignLattice::top();
    // Assign a constant to a variable.
    } else if (const auto *BinOp = Nodes.getNodeAs<clang::BinaryOperator>(kAssignment)) {
      const auto *RHS = BinOp->getRHS();
      Expr::EvalResult R;
      // Not a constant.
      if (!(RHS->EvaluateAsInt(R, Context) && R.Val.isInt())) {
        Vars[Var] = SignLattice::top();
        return;
      }
      Vars[Var] = SignLattice(R.Val.getInt().getExtValue());
    }
  }
};

using ::testing::IsEmpty;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

MATCHER_P(Var, name,
          (llvm::Twine(negation ? "isn't" : "is") + " a variable named `" +
           name + "`")
              .str()) {
  assert(isa<VarDecl>(arg));
  return arg->getName() == name;
}

MATCHER_P(HasConstantVal, v, "") { return arg.Value && *arg.Value == v; }

MATCHER(Bottom, "") { return arg == arg.bottom(); }
MATCHER(Negative, "") { return arg == arg.negative(); }
MATCHER(Zero, "") { return arg == arg.zero(); }
MATCHER(Positive, "") { return arg == arg.positive(); }
MATCHER(Top, "") { return arg == arg.top(); }

MATCHER_P(HoldsSignLattice, m,
          ((negation ? "doesn't hold" : "holds") +
           llvm::StringRef(" a lattice element that ") +
           ::testing::DescribeMatcher<ConstantPropagationLattice>(m, negation))
              .str()) {
  return ExplainMatchResult(m, arg.Lattice, result_listener);
}

template <typename Matcher>
void RunDataflow(llvm::StringRef Code, Matcher Expectations) {
  ASSERT_THAT_ERROR(
      test::checkDataflow<ConstantPropagationAnalysis>(
          Code, "fun",
          [](ASTContext &C, Environment &) {
            return ConstantPropagationAnalysis(C);
          },
          [&Expectations](
              llvm::ArrayRef<std::pair<
                  std::string,
                  DataflowAnalysisState<ConstantPropagationAnalysis::Lattice>>>
                  Results,
              ASTContext &) { EXPECT_THAT(Results, Expectations); },
          {"-fsyntax-only", "-std=c++17"}),
      llvm::Succeeded());
}

TEST(SignAnalysisTest, JustInit) {
  std::string Code = R"(
    void fun() {
      int neg = -1;
      int zero = 0;
      int pos = 1;
      int uninited;
      // [[p]]
    }
  )";
  RunDataflow(Code, UnorderedElementsAre(
                        Pair("p", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("neg"), Negative()),
                                      Pair(Var("zero"), Zero()),
                                      Pair(Var("pos"), Positive()),
                                      Pair(Var("uninited"), Top())
                                      )))));
}

TEST(SignAnalysisTest, Bottom) {
  std::string Code = R"(
    int foo();
    void fun() {
      int a = foo();
      // [[p]]
    }
  )";
  RunDataflow(Code, UnorderedElementsAre(
                        Pair("p", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Bottom())
                                      )))));
}

TEST(SignAnalysisTest, GreaterThan) {
  std::string Code = R"(
    int foo();
    void fun() {
      int a = foo();
      if (a > 0) {
        (void)0;
        // [[p]]
      }
      if (a > -1) {
        (void)0;
        // [[q]]
      }
    }
  )";
  RunDataflow(Code, UnorderedElementsAre(
                        Pair("p", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Positive())
                                      ))),
                        Pair("q", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Top())
                                      )))
                        ));
}

TEST(SignAnalysisTest, GreaterThanIfElse) {
  std::string Code = R"(
    void fun(int a) {
      if (a > 0) {
        (void)1;
        // [[p]]
      } else {
        (void)0;
        // [[q]]
      }
    }
  )";
  RunDataflow(Code, UnorderedElementsAre(
                        Pair("p", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Positive())
                                      ))),
                        Pair("q", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Top())
                                      )))
                        ));
}


TEST(SignAnalysisTest, Equality) {
  std::string Code = R"(
    int foo();
    void fun() {
      int a = foo();
      if (a == -1) {
        (void)0;
        // [[n]]
      }
      if (a == 0) {
        (void)0;
        // [[z]]
      }
      if (a == 1) {
        (void)0;
        // [[p]]
      }
    }
  )";
  RunDataflow(Code, UnorderedElementsAre(
                        Pair("n", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Negative())))),
                        Pair("z", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Zero())))),
                        Pair("p", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Positive()))))
                                      ));
}

TEST(SignAnalysisTest, SymbolicAssignment) {
  std::string Code = R"(
    int foo();
    void fun() {
      int a = foo();
      int b = foo();
      if (a < 0) {
        b = a;
        (void)0;
        // [[p]]
      }
    }
  )";
  RunDataflow(Code, UnorderedElementsAre(
                        Pair("p", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Negative()),
                                      Pair(Var("b"), Negative())
                                      )))));
}

TEST(SignAnalysisTest, Assignment) {
  std::string Code = R"(
    int foo();
    void fun(bool b) {
      int a = foo();
      a = -1;
      // [[p]]
    }
  )";
  RunDataflow(Code, UnorderedElementsAre(
                        Pair("p", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Negative()))))
                                      ));
}

TEST(SignAnalysisTest, Join) {
  std::string Code = R"(
    int foo();
    void fun(bool b) {
      int a = foo();
      if (b) {
        a = -1;
        (void)0;
        // [[p]]
      } else {
        a = 1;
        (void)0;
        // [[q]]
      }
      (void)0;
      // [[r]]
    }
  )";
  RunDataflow(Code, UnorderedElementsAre(
                        Pair("p", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Negative())))),
                        Pair("q", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Positive())))),
                        Pair("r", HoldsSignLattice(UnorderedElementsAre(
                                      Pair(Var("a"), Top()))))
                                      ));
}

} // namespace
} // namespace dataflow
} // namespace clang
