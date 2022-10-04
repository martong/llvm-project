//===- unittests/Analysis/FlowSensitive/SignAnalysisTest.cpp --===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defines a simplistic version of Sign Analysis as an example
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
#include "clang/Analysis/FlowSensitive/CFGMatchSwitch.h"
#include "clang/Analysis/FlowSensitive/DataflowAnalysis.h"
#include "clang/Analysis/FlowSensitive/DataflowEnvironment.h"
#include "clang/Analysis/FlowSensitive/DataflowLattice.h"
#include "clang/Analysis/FlowSensitive/NoopAnalysis.h"
#include "clang/Analysis/FlowSensitive/NoopLattice.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/None.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/Error.h"
#include "llvm/Testing/Support/Annotations.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

namespace {

using namespace clang;
using namespace dataflow;
using namespace ast_matchers;
using namespace test;
using ::testing::UnorderedElementsAre;

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

  constexpr SignLattice() : State(SignState::Bottom) {}
  constexpr SignLattice(int64_t V)
      : State(V == 0 ? SignState::Zero
                     : (V < 0 ? SignState::Negative : SignState::Positive)) {}
  constexpr SignLattice(SignState S) : State(S) {}

  static constexpr SignLattice bottom() {
    return SignLattice(SignState::Bottom);
  }
  static constexpr SignLattice negative() {
    return SignLattice(SignState::Negative);
  }
  static constexpr SignLattice zero() { return SignLattice(SignState::Zero); }
  static constexpr SignLattice positive() {
    return SignLattice(SignState::Positive);
  }
  static constexpr SignLattice top() { return SignLattice(SignState::Top); }
};

using LatticeTransferState = TransferState<NoopLattice>;

constexpr char kVar[] = "var";
constexpr char kInit[] = "init";

Value *getValue(const VarDecl *Var, const LatticeTransferState &State) {
  const StorageLocation *Loc =
      State.Env.getStorageLocation(*Var, SkipPast::None);
  assert(isa_and_nonnull<ScalarStorageLocation>(Loc));
  Value *Val = State.Env.getValue(*Loc);
  // int A = -1; // IntegerValue
  // int B = 0;  // BoolValue
  // int C = 1;  // BoolValue
  assert((isa_and_nonnull<IntegerValue, BoolValue>(Val)));
  return Val;
}

void initNegative(Value &Val, Environment &Env) {
    Val.setProperty("neg", Env.getBoolLiteralValue(true));
    Val.setProperty("zero", Env.getBoolLiteralValue(false));
    Val.setProperty("pos", Env.getBoolLiteralValue(false));
}
void initPositive(Value &Val, Environment &Env) {
    Val.setProperty("neg", Env.getBoolLiteralValue(false));
    Val.setProperty("zero", Env.getBoolLiteralValue(false));
    Val.setProperty("pos", Env.getBoolLiteralValue(true));
}
void initZero(Value &Val, Environment &Env) {
    Val.setProperty("neg", Env.getBoolLiteralValue(false));
    Val.setProperty("zero", Env.getBoolLiteralValue(true));
    Val.setProperty("pos", Env.getBoolLiteralValue(false));
}

struct SignProperties {
  BoolValue *Neg, *Zero, *Pos;
};
SignProperties initUnknown(Value &Val, Environment &Env) {
  SignProperties Ps{&Env.makeAtomicBoolValue(), &Env.makeAtomicBoolValue(),
                    &Env.makeAtomicBoolValue()};
  Val.setProperty("neg", *Ps.Neg);
  Val.setProperty("zero", *Ps.Zero);
  Val.setProperty("pos", *Ps.Pos);
  return Ps;
}
SignProperties getSignProperties(const Value &Val, Environment &Env) {
  return {
    dyn_cast_or_null<BoolValue>(Val.getProperty("neg")),
    dyn_cast_or_null<BoolValue>(Val.getProperty("zero")),
    dyn_cast_or_null<BoolValue>(Val.getProperty("pos"))};
}

void transferUninitializedInt(const DeclStmt *D,
                              const MatchFinder::MatchResult &M,
                              LatticeTransferState &State) {
  const auto *Var = M.Nodes.getNodeAs<clang::VarDecl>(kVar);
  assert(Var != nullptr);
  const StorageLocation *Loc =
      State.Env.getStorageLocation(*Var, SkipPast::None);
  Value *Val = State.Env.getValue(*Loc);
  initUnknown(*Val, State.Env);
}

std::tuple<Value *, SignProperties, SignProperties>
getValueAndSignProperties(const UnaryOperator *UO,
                          const MatchFinder::MatchResult &M,
                          LatticeTransferState &State) {
  // The DeclRefExpr refers to this variable in the operand.
  const auto *OpdVar = M.Nodes.getNodeAs<clang::VarDecl>(kVar);
  assert(OpdVar != nullptr);
  const auto *OperandVal = State.Env.getValue(*OpdVar, SkipPast::None);
  if (!OperandVal)
    return {nullptr, {}, {}};

  // Value of the unary op.
  auto *UOVal = State.Env.getValue(*UO, SkipPast::None);
  if (!UOVal) {
    auto &Loc = State.Env.createStorageLocation(*UO);
    State.Env.setStorageLocation(*UO, Loc);
    UOVal = &State.Env.makeAtomicBoolValue();
    State.Env.setValue(Loc, *UOVal);
  }

  // Properties for the operand (sub expression).
  SignProperties OpdPs = getSignProperties(*OperandVal, State.Env);
  if (!OpdPs.Neg)
    return {nullptr, {}, {}};
  // Properties for the operator expr itself.
  SignProperties UOPs = initUnknown(*UOVal, State.Env);
  return {UOVal, UOPs, OpdPs};
}

void transferUnaryMinus(const UnaryOperator *UO,
                                 const MatchFinder::MatchResult &M,
                                 LatticeTransferState &State) {
  auto [UOVal, UOPs, OpdPs] = getValueAndSignProperties(UO, M, State);
  if (!UOVal)
    return;

  // a is pos ==> -a is neg
  State.Env.addToFlowCondition(
      State.Env.makeImplication(*OpdPs.Pos, *UOPs.Neg));
  // a is neg ==> -a is pos
  State.Env.addToFlowCondition(
      State.Env.makeImplication(*OpdPs.Neg, *UOPs.Pos));
  // a is zero ==> -a is zero
  State.Env.addToFlowCondition(
      State.Env.makeImplication(*OpdPs.Zero, *UOPs.Zero));
}

void transferUnaryNot(const UnaryOperator *UO,
                                 const MatchFinder::MatchResult &M,
                                 LatticeTransferState &State) {
  auto [UOVal, UOPs, OpdPs] = getValueAndSignProperties(UO, M, State);
  if (!UOVal)
    return;

  // a is neg or pos ==> !a is zero
  State.Env.addToFlowCondition(State.Env.makeImplication(
      State.Env.makeOr(*OpdPs.Pos, *OpdPs.Neg), *UOPs.Zero));

  if (auto *UOBoolVal = dyn_cast<BoolValue>(UOVal)) {
    // !a <==> a is zero
    State.Env.addToFlowCondition(State.Env.makeIff(*UOBoolVal, *OpdPs.Zero));
    // !a <==> !a is not zero
    State.Env.addToFlowCondition(
        State.Env.makeIff(*UOBoolVal, State.Env.makeNot(*UOPs.Zero)));
  }
}

void transferExpr(const Expr *E,
                                 const MatchFinder::MatchResult &M,
                                 LatticeTransferState &State) {
  const ASTContext &Context = *M.Context;
  StorageLocation *Loc =
      State.Env.getStorageLocation(*E, SkipPast::None);
  if (!Loc) {
    Loc = &State.Env.createStorageLocation(*E);
    State.Env.setStorageLocation(*E, *Loc);
  }
  Value *Val = State.Env.getValue(*Loc);
  if (!Val) {
    Val = State.Env.createValue(Context.IntTy);
    State.Env.setValue(*Loc, *Val);
  }
  // The sign symbolic values have been initialized already.
  if (Val->getProperty("neg"))
    return;

  Expr::EvalResult R;
  // An integer expression which we cannot evaluate.
  if (!(E->EvaluateAsInt(R, Context) && R.Val.isInt())) {
    initUnknown(*Val, State.Env);
    return;
  }

  const SignLattice L = SignLattice(R.Val.getInt().getExtValue());
  switch (L.State) {
  case SignLattice::SignState::Negative:
    initNegative(*Val, State.Env);
    break;
  case SignLattice::SignState::Zero:
    initZero(*Val, State.Env);
    break;
  case SignLattice::SignState::Positive:
    initPositive(*Val, State.Env);
    break;
  case SignLattice::SignState::Top:
    llvm_unreachable("should not be top here");
    break;
  case SignLattice::SignState::Bottom:
    llvm_unreachable("should not be bottom here");
    break;
  }
}

auto refToVar() { return declRefExpr(to(varDecl().bind(kVar))); }

auto buildTransferMatchSwitch() {
  return CFGMatchSwitchBuilder<LatticeTransferState>()

      // -a
      .CaseOfCFGStmt<UnaryOperator>(
          unaryOperator(hasOperatorName("-"),
                        hasUnaryOperand(hasDescendant(refToVar()))),
          transferUnaryMinus)

      // !a
      .CaseOfCFGStmt<UnaryOperator>(
          unaryOperator(hasOperatorName("!"),
                        hasUnaryOperand(hasDescendant(refToVar()))),
          transferUnaryNot)

      // int a;
      .CaseOfCFGStmt<DeclStmt>(
          declStmt(hasSingleDecl(
              varDecl(decl().bind(kVar), hasType(isInteger()),
                      unless(hasInitializer(expr()))))),
          transferUninitializedInt)

      // constexpr int
      .CaseOfCFGStmt<Expr>(
          expr(hasType(isInteger())),
          transferExpr)

      .Build();
}

class SignPropagationAnalysis
    : public DataflowAnalysis<SignPropagationAnalysis, NoopLattice> {
public:
  SignPropagationAnalysis(ASTContext &Context)
      : DataflowAnalysis<SignPropagationAnalysis, NoopLattice>(
             Context),
      TransferMatchSwitch(buildTransferMatchSwitch()) {}

  static NoopLattice initialElement() { return {}; }

  void transfer(const CFGElement *Elt, NoopLattice &L, Environment &Env) {
    LatticeTransferState State(L, Env);
    TransferMatchSwitch(*Elt, getASTContext(), State);
  }
private:
  CFGMatchSwitch<TransferState<NoopLattice>> TransferMatchSwitch;
};

template <typename Matcher>
void runDataflow(llvm::StringRef Code, Matcher Match,
                 LangStandard::Kind Std = LangStandard::lang_cxx17,
                 llvm::StringRef TargetFun = "fun") {
  using ast_matchers::hasName;
  ASSERT_THAT_ERROR(
      checkDataflow<SignPropagationAnalysis>(
          AnalysisInputs<SignPropagationAnalysis>(Code, hasName(TargetFun),
                                       [](ASTContext &C, Environment &) {
                                         return SignPropagationAnalysis(C);
                                       })
              .withASTBuildArgs(
                  {"-fsyntax-only", "-fno-delayed-template-parsing",
                   "-std=" +
                       std::string(LangStandard::getLangStandardForKind(Std)
                                       .getName())}),
          /*VerifyResults=*/
          [&Match](const llvm::StringMap<DataflowAnalysisState<NoopLattice>>
                       &Results,
                   const AnalysisOutputs &AO) { Match(Results, AO.ASTCtx); }),
      llvm::Succeeded());
}

// FIXME add this to testing support.
template <typename NodeType, typename MatcherType>
const NodeType *findFirst(ASTContext &ASTCtx, const MatcherType &M) {
  auto TargetNodes = match(M.bind("v"), ASTCtx);
  assert(TargetNodes.size() == 1 && "Match must be unique");
  auto *const Result = selectFirst<NodeType>("v", TargetNodes);
  assert(Result != nullptr);
  return Result;
}

template <typename Node>
std::pair<testing::AssertionResult, Value*> getProperty(const Environment &Env,
                                       ASTContext &ASTCtx, const Node *N,
                                       StringRef Property) {
  if(!N)
    return {testing::AssertionFailure() << "No node", nullptr};
  const StorageLocation *Loc = Env.getStorageLocation(*N, SkipPast::None);
  if (!isa_and_nonnull<ScalarStorageLocation>(Loc))
    return {testing::AssertionFailure() << "No location", nullptr};
  const Value *Val = Env.getValue(*Loc);
  if (!Val)
    return {testing::AssertionFailure() << "No value", nullptr};
  auto *Prop = Val->getProperty(Property);
  if (!isa_and_nonnull<BoolValue>(Prop))
    return {testing::AssertionFailure() << "No property for " << Property,
            nullptr};
  return {testing::AssertionSuccess(), Prop};
}

template <typename Node>
testing::AssertionResult isPropertySet(const Environment &Env,
                                       ASTContext &ASTCtx, const Node *N,
                                       StringRef Property, bool Val) {
  auto [Result, Prop] = getProperty(Env, ASTCtx, N, Property);
  if (!Prop)
    return Result;
  auto *BVProp = cast<BoolValue>(Prop);
  //BVProp = Val ? BVProp : &Env.makeNot(*BVProp);
  if (Env.flowConditionImplies(*BVProp) != Val)
    return testing::AssertionFailure()
           << Property << " is " << (Val ? "not" : "") << " implied"
           << ", but should " << (Val ? "" : "not") << "be";
  return testing::AssertionSuccess();
}

template <typename Node>
testing::AssertionResult isNegative(const Node *N, ASTContext &ASTCtx,
                                    const Environment &Env) {
  testing::AssertionResult R = isPropertySet(Env, ASTCtx, N, "neg", true);
  if(!R)
    return R;
  R = isPropertySet(Env, ASTCtx, N, "zero", false);
  if(!R)
    return R;
  return isPropertySet(Env, ASTCtx, N, "pos", false);
}
template <typename Node>
testing::AssertionResult isPositive(const Node *N, ASTContext &ASTCtx,
                                    const Environment &Env) {
  testing::AssertionResult R = isPropertySet(Env, ASTCtx, N, "pos", true);
  if(!R)
    return R;
  R = isPropertySet(Env, ASTCtx, N, "zero", false);
  if(!R)
    return R;
  return isPropertySet(Env, ASTCtx, N, "neg", false);
}
template <typename Node>
testing::AssertionResult isZero(const Node *N, ASTContext &ASTCtx,
                                const Environment &Env) {
  testing::AssertionResult R = isPropertySet(Env, ASTCtx, N, "zero", true);
  if(!R)
    return R;
  R = isPropertySet(Env, ASTCtx, N, "pos", false);
  if(!R)
    return R;
  return isPropertySet(Env, ASTCtx, N, "neg", false);
}
template <typename Node>
testing::AssertionResult isTop(const Node *N, ASTContext &ASTCtx,
                                const Environment &Env) {
  testing::AssertionResult R = isPropertySet(Env, ASTCtx, N, "zero", false);
  if(!R)
    return R;
  R = isPropertySet(Env, ASTCtx, N, "pos", false);
  if(!R)
    return R;
  return isPropertySet(Env, ASTCtx, N, "neg", false);
}

TEST(SignAnalysisTest, Init) {
  std::string Code = R"(
    int foo();
    void fun() {
      int a = -1;
      int b = 0;
      int c = 1;
      int d;
      int e = foo();
      int f = c;
      // [[p]]
    }
  )";
  runDataflow(Code,
      [](const llvm::StringMap<DataflowAnalysisState<NoopLattice>> &Results,
         ASTContext &ASTCtx) {
        //ASTCtx.getTranslationUnitDecl()->dump();
        ASSERT_THAT(Results.keys(), UnorderedElementsAre("p"));
        const Environment &Env = getEnvironmentAtAnnotation(Results, "p");

        const ValueDecl *A = findValueDecl(ASTCtx, "a");
        const ValueDecl *B = findValueDecl(ASTCtx, "b");
        const ValueDecl *C = findValueDecl(ASTCtx, "c");
        const ValueDecl *D = findValueDecl(ASTCtx, "d");
        const ValueDecl *E = findValueDecl(ASTCtx, "e");
        const ValueDecl *F = findValueDecl(ASTCtx, "f");

        EXPECT_TRUE(isNegative(A, ASTCtx, Env));
        EXPECT_TRUE(isZero(B, ASTCtx, Env));
        EXPECT_TRUE(isPositive(C, ASTCtx, Env));
        EXPECT_TRUE(isTop(D, ASTCtx, Env));
        EXPECT_TRUE(isTop(E, ASTCtx, Env));
        EXPECT_TRUE(isPositive(F, ASTCtx, Env));
      },
      LangStandard::lang_cxx17);
}

TEST(SignAnalysisTest, UnaryMinus) {
  std::string Code = R"(
    void fun() {
      int a = 1;
      int b = -a;
      // [[p]]
    }
  )";
  runDataflow(Code,
      [](const llvm::StringMap<DataflowAnalysisState<NoopLattice>> &Results,
         ASTContext &ASTCtx) {
        ASSERT_THAT(Results.keys(), UnorderedElementsAre("p"));
        const Environment &Env = getEnvironmentAtAnnotation(Results, "p");

        const ValueDecl *A = findValueDecl(ASTCtx, "a");
        const ValueDecl *B = findValueDecl(ASTCtx, "b");
        EXPECT_TRUE(isPositive(A, ASTCtx, Env));
        EXPECT_TRUE(isNegative(B, ASTCtx, Env));
      },
      LangStandard::lang_cxx17);
}

TEST(SignAnalysisTest, UnaryNot) {
  std::string Code = R"(
    void fun() {
      int a = 2;
      int b = !a;
      // [[p]]
    }
  )";
  runDataflow(Code,
      [](const llvm::StringMap<DataflowAnalysisState<NoopLattice>> &Results,
         ASTContext &ASTCtx) {
        ASSERT_THAT(Results.keys(), UnorderedElementsAre("p"));
        const Environment &Env = getEnvironmentAtAnnotation(Results, "p");

        const ValueDecl *A = findValueDecl(ASTCtx, "a");
        const ValueDecl *B = findValueDecl(ASTCtx, "b");
        EXPECT_TRUE(isPositive(A, ASTCtx, Env));
        EXPECT_TRUE(isZero(B, ASTCtx, Env));
      },
      LangStandard::lang_cxx17);
}

TEST(SignAnalysisTest, UnaryNotInIf) {
  std::string Code = R"(
    int foo();
    void fun() {
      int a = foo();
      if (!a) {
        int b1;
        int p_a = a;
        int p_not_a = !a;
        // [[p]]
      } else {
        int q_a = a;
        int q_not_a = !a;
        // [[q]]
      }
    }
  )";
  runDataflow(Code,
      [](const llvm::StringMap<DataflowAnalysisState<NoopLattice>> &Results,
         ASTContext &ASTCtx) {
        ASSERT_THAT(Results.keys(), UnorderedElementsAre("p", "q"));
        const Environment &EnvP = getEnvironmentAtAnnotation(Results, "p");
        const Environment &EnvQ = getEnvironmentAtAnnotation(Results, "q");

        const ValueDecl *A = findValueDecl(ASTCtx, "a");
        const ValueDecl *PA = findValueDecl(ASTCtx, "p_a");
        const ValueDecl *PNA = findValueDecl(ASTCtx, "p_not_a");
        const ValueDecl *QA = findValueDecl(ASTCtx, "q_a");
        const ValueDecl *QNA = findValueDecl(ASTCtx, "q_not_a");

        // p
        EXPECT_TRUE(isZero(A, ASTCtx, EnvP));
        EXPECT_TRUE(isZero(PA, ASTCtx, EnvP));
        EXPECT_TRUE(isTop(PNA, ASTCtx, EnvP));

        // q
        EXPECT_TRUE(isTop(A, ASTCtx, EnvQ));
        EXPECT_TRUE(isTop(QA, ASTCtx, EnvQ));
        EXPECT_TRUE(isZero(QNA, ASTCtx, EnvQ));
      },
      LangStandard::lang_cxx17);
}

} // namespace
