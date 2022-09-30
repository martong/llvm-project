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
#include "gmock/gmock.h"
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
using ::testing::NotNull;
using ::testing::IsEmpty;
using ::testing::Pair;
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
void initTop(Value &Val, Environment &Env) {
    Val.setProperty("neg", Env.getBoolLiteralValue(false));
    Val.setProperty("zero", Env.getBoolLiteralValue(false));
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
void setSignProperties(Value &Val, Environment &Env,
                       const SignProperties &Props) {
  Val.setProperty("neg", *Props.Neg);
  Val.setProperty("zero", *Props.Zero);
  Val.setProperty("pos", *Props.Pos);
}

void initializeInteger(const DeclStmt *D, const MatchFinder::MatchResult &M,
                       LatticeTransferState &State) {
  const auto *Var = M.Nodes.getNodeAs<clang::VarDecl>(kVar);
  assert(Var != nullptr);

  const StorageLocation *Loc =
      State.Env.getStorageLocation(*Var, SkipPast::None);
  assert(isa_and_nonnull<ScalarStorageLocation>(Loc));
  Value *Val = State.Env.getValue(*Loc);
  // int A = -1; // IntegerValue
  // int B = 0;  // BoolValue
  // int C = 1;  // BoolValue
  assert((isa_and_nonnull<IntegerValue, BoolValue>(Val)));

  const ASTContext &Context = *M.Context;
  SignLattice L;

  if (const auto *InitE = M.Nodes.getNodeAs<clang::Expr>(kInit)) {
    Expr::EvalResult R;
    // Initialized with a constant.
    if (InitE->EvaluateAsInt(R, Context) && R.Val.isInt()) {
      L = SignLattice(R.Val.getInt().getExtValue());
    } else { // Initialized with an arbitrary expression.
      // Get the stored properties of the init expression and assign them to
      // this variable as well, if the sign properties are set.
      if (Value *InitVal = State.Env.getValue(*InitE, SkipPast::None))
        if (InitVal->getProperty(
                "neg")) { // If one property is set then the rest is also set.
          // Properties are bound to the value of the init expression.
          State.Env.setValue(*Loc, *InitVal);
          return;
        }

      // Initialize to top, if we don't know anything about the init expr.
      L = SignLattice::top();
    }
  } else { // Uninitialized.
    // An unitialized variable holds *some* value, but we don't know what it
    // is (it is implementation defined), so we set it to top.
    L = SignLattice::top();
  }

  switch (L.State) {
  case SignLattice::SignState::Bottom:
    break;
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
    initUnknown(*Val, State.Env);
    break;
  }

}

void transferIntegerLiteral(const IntegerLiteral *I,
                                 const MatchFinder::MatchResult &M,
                                 LatticeTransferState &State) {
  auto &Loc = State.Env.createStorageLocation(*I);
  State.Env.setStorageLocation(*I, Loc);
  BoolValue &V = State.Env.makeAtomicBoolValue();
  State.Env.setValue(Loc, V);
  if (I->getValue().isZero())
    V.setProperty("zero", State.Env.getBoolLiteralValue(true));
  else
    V.setProperty("pos", State.Env.getBoolLiteralValue(true));
}

void transferUnaryMinus(const UnaryOperator *UO,
                                 const MatchFinder::MatchResult &M,
                                 LatticeTransferState &State) {
  const auto *OperandVal = dyn_cast_or_null<BoolValue>(
      State.Env.getValue(*UO->getSubExpr(), SkipPast::None));
  if (!OperandVal)
    return;

  auto *UOVal = State.Env.getValue(*UO, SkipPast::None);
  if(!UOVal) {
    // FIXME hoist copy paste
    auto &Loc = State.Env.createStorageLocation(*UO);
    State.Env.setStorageLocation(*UO, Loc);
    UOVal = &State.Env.makeAtomicBoolValue();
    State.Env.setValue(Loc, *UOVal);
  }

  SignProperties OpdPs = getSignProperties(*OperandVal, State.Env);
  SignProperties UOPs = initUnknown(*UOVal, State.Env);

  // a is pos ==> -a is neg
  if (OpdPs.Pos)
    State.Env.addToFlowCondition(
        State.Env.makeImplication(*OpdPs.Pos, *UOPs.Neg));
  // a is neg ==> -a is pos
  if (OpdPs.Neg)
    State.Env.addToFlowCondition(
        State.Env.makeImplication(*OpdPs.Neg, *UOPs.Pos));
  // a is zero ==> -a is zero
  if (OpdPs.Zero)
    State.Env.addToFlowCondition(
        State.Env.makeImplication(*OpdPs.Zero, *UOPs.Zero));
}

void transferUnaryNot(const UnaryOperator *UO,
                                 const MatchFinder::MatchResult &M,
                                 LatticeTransferState &State) {
  // The DeclRefExpr refers to this variable in the operand.
  const auto *OpdVar = M.Nodes.getNodeAs<clang::VarDecl>(kVar);
  assert(OpdVar != nullptr);
  const auto *OperandVal = State.Env.getValue(*OpdVar, SkipPast::None);
  if (!OperandVal)
    return;

  auto *UOVal = State.Env.getValue(*UO, SkipPast::None);
  if(!UOVal) {
    // FIXME hoist copy paste
    auto &Loc = State.Env.createStorageLocation(*UO);
    State.Env.setStorageLocation(*UO, Loc);
    UOVal = &State.Env.makeAtomicBoolValue();
    State.Env.setValue(Loc, *UOVal);
  }

  SignProperties OpdPs = getSignProperties(*OperandVal, State.Env);
  SignProperties UOPs = initUnknown(*UOVal, State.Env);

  if (!OpdPs.Zero || !OpdPs.Pos || !OpdPs.Neg)
    return;

  if (auto *UOBoolVal = dyn_cast<BoolValue>(UOVal)) {
    // !a is true  <==> a is zero
    State.Env.addToFlowCondition(State.Env.makeIff(*UOBoolVal, *OpdPs.Zero));
    // !a is true <==> !a is not zero
    State.Env.addToFlowCondition(
        State.Env.makeIff(*UOBoolVal, State.Env.makeNot(*UOPs.Zero)));
  }
}

void transferUnaryNot_old(const UnaryOperator *Op,
                                 const MatchFinder::MatchResult &M,
                                 LatticeTransferState &State) {
  const auto *Var = M.Nodes.getNodeAs<clang::VarDecl>(kVar);
  assert(Var != nullptr);

  // Boolean representing the comparison between the two pointer values,
  // automatically created by the dataflow framework
  auto& Cond =
      *cast<BoolValue>(State.Env.getValue(*Op, SkipPast::None));

  Value *Val = getValue(Var, State);
  assert(Val);

  //BoolValue *BVal = dyn_cast<BoolValue>(Val);
  //if (!BVal) {
    //IntegerValue *IV = cast<IntegerValue>(Val);
    //// FIXME How to convert to BoolValue?
    //// If IntegerValue stored the concrete integer, e.g. 42 in case of
    //// `int a = 42` then we could convert it to a BoolValue.
  //}

  BoolValue &ZeroProp = State.Env.makeAtomicBoolValue();
  Val->setProperty("zero", ZeroProp);
  // !a is true ==> a is zero
  State.Env.addToFlowCondition(State.Env.makeImplication(Cond, ZeroProp));

  BoolValue &TopProp = State.Env.makeAtomicBoolValue();
  Val->setProperty("top", TopProp);
  // !a is false ==> a is top (can be both negative or positive)
  State.Env.addToFlowCondition(
      State.Env.makeImplication(State.Env.makeNot(Cond), TopProp));
}

auto refToVar() { return declRefExpr(to(varDecl().bind(kVar))); }

auto buildTransferMatchSwitch() {
  return CFGMatchSwitchBuilder<LatticeTransferState>()
      .CaseOfCFGStmt<IntegerLiteral>(integerLiteral(), transferIntegerLiteral)
      .CaseOfCFGStmt<UnaryOperator>(
          unaryOperator(hasOperatorName("-")),
          transferUnaryMinus)
      .CaseOfCFGStmt<DeclStmt>(
          declStmt(hasSingleDecl(
              varDecl(decl().bind(kVar), hasType(isInteger()),
                      optionally(hasInitializer(expr().bind(kInit))))
                  )),
          initializeInteger)
      .CaseOfCFGStmt<UnaryOperator>(
          unaryOperator(hasOperatorName("!"),
                        hasUnaryOperand(hasDescendant(refToVar()))),
          transferUnaryNot)

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

TEST(SignAnalysisTest, BasicLiterals) {
  std::string Code = R"(
    void fun() {
      2;
      1;
      0;
      // [[p]]
    }
  )";
  runDataflow(Code,
      [](const llvm::StringMap<DataflowAnalysisState<NoopLattice>> &Results,
         ASTContext &ASTCtx) {
        ASSERT_THAT(Results.keys(), UnorderedElementsAre("p"));
        const Environment &Env = getEnvironmentAtAnnotation(Results, "p");

        const auto *Two = findFirst<IntegerLiteral>(ASTCtx, integerLiteral(equals(2)));
        const auto *One = findFirst<IntegerLiteral>(ASTCtx, integerLiteral(equals(1)));
        const auto *Zero = findFirst<IntegerLiteral>(ASTCtx, integerLiteral(equals(0)));
        EXPECT_TRUE(isPositive(Two, ASTCtx, Env));
        EXPECT_TRUE(isPositive(One, ASTCtx, Env));
        EXPECT_TRUE(isZero(Zero, ASTCtx, Env));
      },
      LangStandard::lang_cxx17);
}

TEST(SignAnalysisTest, UnaryLiterals) {
  std::string Code = R"(
    void fun() {
      -1;
      // [[p]]
    }
  )";
  runDataflow(Code,
      [](const llvm::StringMap<DataflowAnalysisState<NoopLattice>> &Results,
         ASTContext &ASTCtx) {
        ASSERT_THAT(Results.keys(), UnorderedElementsAre("p"));
        const Environment &Env = getEnvironmentAtAnnotation(Results, "p");

        const auto *MinusOne = findFirst<UnaryOperator>(ASTCtx, unaryOperator());
        EXPECT_TRUE(isNegative(MinusOne, ASTCtx, Env));
      },
      LangStandard::lang_cxx17);
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
      int b = a;
      int c = -a;
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
        const ValueDecl *C = findValueDecl(ASTCtx, "c");
        EXPECT_TRUE(isPositive(A, ASTCtx, Env));
        EXPECT_TRUE(isPositive(B, ASTCtx, Env));
        EXPECT_TRUE(isNegative(C, ASTCtx, Env));
      },
      LangStandard::lang_cxx17);
}

TEST(SignAnalysisTest, UnaryNot) {
  std::string Code = R"(
    int foo();
    void fun() {
      int a = foo();
      if (!a) {
        int b1;
        b1 = !a;
        // [[p]]
      } else {
        int b2;
        b2 = !a;
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
        const ValueDecl *B1 = findValueDecl(ASTCtx, "b1");
        const ValueDecl *B2 = findValueDecl(ASTCtx, "b2");

        // p
        EXPECT_TRUE(isZero(A, ASTCtx, EnvP));
        EXPECT_TRUE(isTop(B1, ASTCtx, EnvP));

        // q
        EXPECT_TRUE(isTop(A, ASTCtx, EnvQ));
        EXPECT_TRUE(isZero(B2, ASTCtx, EnvQ));
      },
      LangStandard::lang_cxx17);
}

} // namespace
