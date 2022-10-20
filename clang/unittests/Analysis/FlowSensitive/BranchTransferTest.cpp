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
#include "clang/Analysis/FlowSensitive/DataflowAnalysis.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/Optional.h"
#include "llvm/Support/Error.h"
#include "llvm/Testing/Support/Annotations.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"

namespace clang {
namespace dataflow {
namespace {
using namespace ast_matchers;
using namespace test;

struct TestLattice {
  enum class Branch : int {
    True,
    False
  };
  llvm::Optional<Branch> TheBranch;
  static TestLattice bottom() { return {}; }

  // Does not matter for this test, but we must provide some definition of join.
  LatticeJoinEffect join(const TestLattice &Other) {
    return LatticeJoinEffect::Unchanged;
  }
  friend bool operator==(const TestLattice &Lhs, const TestLattice &Rhs) {
    return Lhs.TheBranch == Rhs.TheBranch;
  }
};

class TestPropagationAnalysis
    : public DataflowAnalysis<TestPropagationAnalysis, TestLattice> {
public:
  explicit TestPropagationAnalysis(ASTContext &Context)
      : DataflowAnalysis<TestPropagationAnalysis, TestLattice>(
            Context) {}
  static TestLattice initialElement() {
    return TestLattice::bottom();
  }
  void branchTransfer(bool Branch, const Stmt *S, TestLattice &L,
                      Environment &Env) {
    L.TheBranch =
        Branch ? TestLattice::Branch::True : TestLattice::Branch::False;
  }
};

using ::testing::UnorderedElementsAre;

MATCHER_P(Var, name,
          (llvm::Twine(negation ? "isn't" : "is") + " a variable named `" +
           name + "`")
              .str()) {
  assert(isa<VarDecl>(arg));
  return arg->getName() == name;
}

template <typename Matcher>
void runDataflow(llvm::StringRef Code, Matcher Match,
                 LangStandard::Kind Std = LangStandard::lang_cxx17,
                 llvm::StringRef TargetFun = "fun") {
  using ast_matchers::hasName;
  ASSERT_THAT_ERROR(
      checkDataflow<TestPropagationAnalysis>(
          AnalysisInputs<TestPropagationAnalysis>(
              Code, hasName(TargetFun),
              [](ASTContext &C, Environment &) {
                return TestPropagationAnalysis(C);
              })
              .withASTBuildArgs(
                  {"-fsyntax-only", "-fno-delayed-template-parsing",
                   "-std=" +
                       std::string(LangStandard::getLangStandardForKind(Std)
                                       .getName())}),
          /*VerifyResults=*/
          [&Match](const llvm::StringMap<DataflowAnalysisState<TestLattice>>
                       &Results,
                   const AnalysisOutputs &AO) { Match(Results, AO.ASTCtx); }),
      llvm::Succeeded());
}

template <typename LatticeT>
const LatticeT &getLatticeAtAnnotation(
    const llvm::StringMap<DataflowAnalysisState<LatticeT>> &AnnotationStates,
    llvm::StringRef Annotation) {
  auto It = AnnotationStates.find(Annotation);
  assert(It != AnnotationStates.end());
  return It->getValue().Lattice;
}

TEST(BranchTransferTest, IfElse) {
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
  runDataflow(
      Code,
      [](const llvm::StringMap<DataflowAnalysisState<TestLattice>> &Results,
         ASTContext &ASTCtx) {
        ASSERT_THAT(Results.keys(), UnorderedElementsAre("p", "q"));

        const TestLattice &LP = getLatticeAtAnnotation(Results, "p");
        EXPECT_TRUE(LP.TheBranch == TestLattice::Branch::True);

        const TestLattice &LQ = getLatticeAtAnnotation(Results, "q");
        EXPECT_TRUE(LQ.TheBranch == TestLattice::Branch::False);
      },
      LangStandard::lang_cxx17);
}

} // namespace
} // namespace dataflow
} // namespace clang
