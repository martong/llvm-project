//=== StdLibraryFunctionsChecker.cpp - Model standard functions -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker improves modeling of a few simple library functions.
//
// This checker provides a specification format - `Summary' - and
// contains descriptions of some library functions in this format. Each
// specification contains a list of branches for splitting the program state
// upon call, and range constraints on argument and return-value symbols that
// are satisfied on each branch. This spec can be expanded to include more
// items, like external effects of the function.
//
// The main difference between this approach and the body farms technique is
// in more explicit control over how many branches are produced. For example,
// consider standard C function `ispunct(int x)', which returns a non-zero value
// iff `x' is a punctuation character, that is, when `x' is in range
//   ['!', '/']   [':', '@']  U  ['[', '\`']  U  ['{', '~'].
// `Summary' provides only two branches for this function. However,
// any attempt to describe this range with if-statements in the body farm
// would result in many more branches. Because each branch needs to be analyzed
// independently, this significantly reduces performance. Additionally,
// once we consider a branch on which `x' is in range, say, ['!', '/'],
// we assume that such branch is an important separate path through the program,
// which may lead to false positives because considering this particular path
// was not consciously intended, and therefore it might have been unreachable.
//
// This checker uses eval::Call for modeling pure functions (functions without
// side effets), for which their `Summary' is a precise model. This avoids
// unnecessary invalidation passes. Conflicts with other checkers are unlikely
// because if the function has no other effects, other checkers would probably
// never want to improve upon the modeling done by this checker.
//
// Non-pure functions, for which only partial improvement over the default
// behavior is expected, are modeled via check::PostCall, non-intrusively.
//
// The following standard C functions are currently supported:
//
//   fgetc      getline   isdigit   isupper
//   fread      isalnum   isgraph   isxdigit
//   fwrite     isalpha   islower   read
//   getc       isascii   isprint   write
//   getchar    isblank   ispunct
//   getdelim   iscntrl   isspace
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicSize.h"
#include "llvm/ADT/Statistic.h"

using namespace clang;
using namespace clang::ento;

namespace {

#define DEBUG_TYPE "StdLibraryFunctionsChecker"
STATISTIC(NumCall, "The # of calls handled by the checker");
STATISTIC(NumFoundSummary, "The # of calls with associated summary");
STATISTIC(NumArgConstraintViolated,
          "The # of calls where an arg constraint is violated");
STATISTIC(NumArgConstrained,
          "The # of calls with applied argumentum constraints");
STATISTIC(NumCaseApplied, "The # of calls with applied cases");

class StdLibraryFunctionsChecker
    : public Checker<check::PreCall, check::PostCall, eval::Call> {
  /// Below is a series of typedefs necessary to define function specs.
  /// We avoid nesting types here because each additional qualifier
  /// would need to be repeated in every function spec.
  struct Summary;

  /// Specify how much the analyzer engine should entrust modeling this function
  /// to us. If he doesn't, he performs additional invalidations.
  enum InvalidationKind { NoEvalCall, EvalCallAsPure };

  // The universal integral type to use in value range descriptions.
  // Unsigned to make sure overflows are well-defined.
  typedef uint64_t RangeInt;

  /// Normally, describes a single range constraint, eg. {{0, 1}, {3, 4}} is
  /// a non-negative integer, which less than 5 and not equal to 2. For
  /// `ComparesToArgument', holds information about how exactly to compare to
  /// the argument.
  typedef std::vector<std::pair<RangeInt, RangeInt>> IntRangeVector;

  /// A reference to an argument or return value by its number.
  /// ArgNo in CallExpr and CallEvent is defined as Unsigned, but
  /// obviously uint32_t should be enough for all practical purposes.
  typedef uint32_t ArgNo;
  static const ArgNo Ret;

  class ValueConstraint;

  // Pointer to the ValueConstraint. We need a copyable, polymorphic and
  // default initialize able type (vector needs that). A raw pointer was good,
  // however, we cannot default initialize that. unique_ptr makes the Summary
  // class non-copyable, therefore not an option. Releasing the copyability
  // requirement would render the initialization of the Summary map infeasible.
  using ValueConstraintPtr = std::shared_ptr<ValueConstraint>;

  /// Polymorphic base class that represents a constraint on a given argument
  /// (or return value) of a function. Derived classes implement different kind
  /// of constraints, e.g range constraints or correlation between two
  /// arguments.
  class ValueConstraint {
  public:
    ValueConstraint(ArgNo ArgN) : ArgN(ArgN) {}
    virtual ~ValueConstraint() {}
    /// Apply the effects of the constraint on the given program state. If null
    /// is returned then the constraint is not feasible.
    virtual ProgramStateRef apply(ProgramStateRef State, const CallEvent &Call,
                                  const Summary &Summary,
                                  CheckerContext &C) const = 0;
    virtual ValueConstraintPtr negate() const {
      llvm_unreachable("Not implemented");
    };
    /// Do sanity check on the constraint.
    bool check(const FunctionDecl *FD) const {
      assert((ArgN == Ret || ArgN < FD->getNumParams()) && "Arg out of range!");
      return validate(FD);
    }
    /// Do polymorphic sanity check on the constraint.
    virtual bool validate(const FunctionDecl *FD) const {
      return true;
    }
    virtual bool skip() const { return false; }
    ArgNo getArgNo() const { return ArgN; }

    virtual StringRef getName() const = 0;

  protected:
    ArgNo ArgN; // Argument to which we apply the constraint.
  };

  using RangeFun = RangeInt(const FunctionDecl *, ArgNo, BasicValueFactory &);
  using RangeFunPtr = RangeFun *;
  class LazyRangeInt {
    union {
      RangeInt Int;
      RangeFunPtr Fun;
    } Storage;
    enum { K_Int, K_Fun } Kind;

  public:
    LazyRangeInt(int Int) : Kind(K_Int) { Storage.Int = Int; }
    LazyRangeInt(RangeFunPtr Fun) : Kind(K_Fun) { Storage.Fun = Fun; }
    RangeInt eval(const FunctionDecl *FD, ArgNo ArgN,
                  BasicValueFactory &BVF) const {
      if (Kind == K_Int)
        return Storage.Int;
      return Storage.Fun(FD, ArgN, BVF);
    }
  };

  static RangeInt Max(const FunctionDecl *FD, ArgNo ArgN, BasicValueFactory &BVF) {
    return BVF.getMaxValue(getArgType(FD, ArgN)).getLimitedValue();
  }

  using LazyIntRangeVector = std::vector<std::pair<LazyRangeInt, LazyRangeInt>>;

  /// Given a range, should the argument stay inside or outside this range?
  enum RangeKind { OutOfRange, WithinRange };

  /// Encapsulates a single range on a single symbol within a branch.
  class RangeConstraint : public ValueConstraint {
    RangeKind Kind;      // Kind of range definition.
    mutable IntRangeVector Ranges;
    LazyIntRangeVector LazyRanges;

  public:
    RangeConstraint(ArgNo ArgN, RangeKind Kind, const IntRangeVector &Ranges)
        : ValueConstraint(ArgN), Kind(Kind), Ranges(Ranges) {}

    RangeConstraint(ArgNo ArgN, RangeKind Kind,
                    const LazyIntRangeVector &Ranges)
        : ValueConstraint(ArgN), Kind(Kind), LazyRanges(Ranges) {}

    const IntRangeVector &getRanges(const FunctionDecl *FD,
                                    BasicValueFactory &BVF) const {
      if (Ranges.size())
        return Ranges;
      for (const std::pair<LazyRangeInt, LazyRangeInt> &LazyR : LazyRanges) {
        Ranges.push_back({LazyR.first.eval(FD, ArgN, BVF),
                          LazyR.second.eval(FD, ArgN, BVF)});
      }
      return Ranges;
    }

  private:
    ProgramStateRef applyAsOutOfRange(ProgramStateRef State,
                                      const CallEvent &Call,
                                      const Summary &Summary) const;
    ProgramStateRef applyAsWithinRange(ProgramStateRef State,
                                       const CallEvent &Call,
                                       const Summary &Summary) const;
  public:
    StringRef getName() const override { return "Range"; }
    ProgramStateRef apply(ProgramStateRef State, const CallEvent &Call,
                          const Summary &Summary,
                          CheckerContext &C) const override {
      switch (Kind) {
      case OutOfRange:
        return applyAsOutOfRange(State, Call, Summary);
      case WithinRange:
        return applyAsWithinRange(State, Call, Summary);
      }
      llvm_unreachable("Unknown range kind!");
    }

    ValueConstraintPtr negate() const override {
      RangeConstraint Tmp(*this);
      switch (Kind) {
      case OutOfRange:
        Tmp.Kind = WithinRange;
        break;
      case WithinRange:
        Tmp.Kind = OutOfRange;
        break;
      }
      return std::make_shared<RangeConstraint>(Tmp);
    }

    bool validate(const FunctionDecl *FD) const override {
      assert(getArgType(FD, ArgN)->isIntegralType(FD->getASTContext()) &&
             "This constraint should be applied on an integral type");
      return getArgType(FD, ArgN)->isIntegralType(FD->getASTContext());
    }
  };

  class ComparisonConstraint : public ValueConstraint {
    BinaryOperator::Opcode Opcode;
    ArgNo OtherArgN;

  public:
    virtual StringRef getName() const override { return "Comparison"; };
    ComparisonConstraint(ArgNo ArgN, BinaryOperator::Opcode Opcode,
                         ArgNo OtherArgN)
        : ValueConstraint(ArgN), Opcode(Opcode), OtherArgN(OtherArgN) {}
    ArgNo getOtherArgNo() const { return OtherArgN; }
    BinaryOperator::Opcode getOpcode() const { return Opcode; }
    ProgramStateRef apply(ProgramStateRef State, const CallEvent &Call,
                          const Summary &Summary,
                          CheckerContext &C) const override;
  };

  class NotNullConstraint : public ValueConstraint {
    using ValueConstraint::ValueConstraint;
    // This variable has a role when we negate the constraint.
    bool CannotBeNull = true;

  public:
    StringRef getName() const override { return "NonNull"; }
    ProgramStateRef apply(ProgramStateRef State, const CallEvent &Call,
                          const Summary &Summary,
                          CheckerContext &C) const override {
      SVal V = getArgSVal(Call, getArgNo());
      if (V.isUndef())
        return State;

      DefinedOrUnknownSVal L = V.castAs<DefinedOrUnknownSVal>();
      if (!L.getAs<Loc>())
        return State;

      return State->assume(L, CannotBeNull);
    }

    ValueConstraintPtr negate() const override {
      NotNullConstraint Tmp(*this);
      Tmp.CannotBeNull = !this->CannotBeNull;
      return std::make_shared<NotNullConstraint>(Tmp);
    }

    bool validate(const FunctionDecl *FD) const override {
      assert(getArgType(FD, ArgN)->isPointerType() &&
             "This constraint should be applied only on a pointer type");
      return getArgType(FD, ArgN)->isPointerType();
    }

    bool skip() const override { return false; }
  };

  // Represents a buffer argument with an additional size argument.
  // E.g. the first two arguments here:
  //   ctime_s(char *buffer, rsize_t bufsz, const time_t *time);
  // Another example:
  //   size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
  //   // Here, ptr is the buffer, and its minimum size is `size * nmemb`.
  class BufferSizeConstraint : public ValueConstraint {
    // The argument which holds the size of the buffer.
    ArgNo SizeArgN;
    // The argument which is a multiplier to size. This is set in case of
    // `fread` like functions where the size is computed as a multiplication of
    // two arguments.
    llvm::Optional<ArgNo> SizeMultiplierArgN;
    // The operator we use in apply. This is negated in negate().
    BinaryOperator::Opcode Op = BO_LE;

  public:
    StringRef getName() const override { return "BufferSize"; }
    BufferSizeConstraint(ArgNo BufArgN, ArgNo SizeArgN)
        : ValueConstraint(BufArgN), SizeArgN(SizeArgN) {}

    BufferSizeConstraint(ArgNo BufArgN, ArgNo SizeArgN, ArgNo SizeMulArgN)
        : ValueConstraint(BufArgN), SizeArgN(SizeArgN),
          SizeMultiplierArgN(SizeMulArgN) {}

    ProgramStateRef apply(ProgramStateRef State, const CallEvent &Call,
                          const Summary &Summary,
                          CheckerContext &C) const override {
      SValBuilder &SvalBuilder = C.getSValBuilder();
      // The buffer argument.
      SVal BufV = getArgSVal(Call, getArgNo());
      // The size argument.
      SVal SizeV = getArgSVal(Call, SizeArgN);
      // Multiply with another argument if given.
      if (SizeMultiplierArgN) {
        SVal SizeMulV = getArgSVal(Call, *SizeMultiplierArgN);
        SizeV = SvalBuilder.evalBinOp(State, BO_Mul, SizeV, SizeMulV,
                                      getArgType(Summary.FD, SizeArgN));
      }
      // The dynamic size of the buffer argument, got from the analyzer engine.
      SVal BufDynSize =
          getDynamicSizeWithOffset(State, BufV, C.getSValBuilder());

      SVal Feasible = SvalBuilder.evalBinOp(State, Op, SizeV, BufDynSize,
                                            SvalBuilder.getContext().BoolTy);
      if (auto F = Feasible.getAs<DefinedOrUnknownSVal>())
        return State->assume(*F, true);

      // We can get here only if the size argument or the dynamic size is
      // undefined. But the dynamic size should never be undefined, only
      // unknown. So, here, the size of the argument is undefined, i.e. we
      // cannot apply the constraint. Actually, other checkers like
      // CallAndMessage should catch this situation earlier, because we call a
      // function with an uninitialized argument.
      return nullptr;
    }

    ValueConstraintPtr negate() const override {
      BufferSizeConstraint Tmp(*this);
      Tmp.Op = BinaryOperator::negateComparisonOp(Op);
      return std::make_shared<BufferSizeConstraint>(Tmp);
    }

    bool validate(const FunctionDecl *FD) const override {
      assert(SizeArgN < FD->param_size() && "Size arg out of range!");
      if (SizeMultiplierArgN) {
        assert(*SizeMultiplierArgN < FD->param_size() && "Size mul arg out of range!");
      }
      return true;
    }

  };

  /// The complete list of constraints that defines a single branch.
  typedef std::vector<ValueConstraintPtr> ConstraintSet;

  using ArgTypes = std::vector<QualType>;

  // A placeholder type, we use it whenever we do not care about the concrete
  // type in a Signature.
  const QualType Irrelevant{};
  bool static isIrrelevant(QualType T) { return T.isNull(); }

  // The signature of a function we want to describe with a summary. This is a
  // concessive signature, meaning there may be irrelevant types in the
  // signature which we do not check against a function with concrete types.
  struct Signature {
    const ArgTypes ArgTys;
    const QualType RetTy;
    Signature() {};
    Signature(ArgTypes ArgTys, QualType RetTy) : ArgTys(ArgTys), RetTy(RetTy) {
      assertRetTypeSuitableForSignature(RetTy);
      for (size_t I = 0, E = ArgTys.size(); I != E; ++I) {
        QualType ArgTy = ArgTys[I];
        assertArgTypeSuitableForSignature(ArgTy);
      }
    }
    bool matches(const FunctionDecl *FD) const;
    bool empty() const { return RetTy.isNull() && ArgTys.size() == 0; }

  private:
    static void assertArgTypeSuitableForSignature(QualType T) {
      assert((T.isNull() || !T->isVoidType()) &&
             "We should have no void types in the spec");
      assert((T.isNull() || T.isCanonical()) &&
             "We should only have canonical types in the spec");
    }
    static void assertRetTypeSuitableForSignature(QualType T) {
      assert((T.isNull() || T.isCanonical()) &&
             "We should only have canonical types in the spec");
    }
  };

  using Cases = std::vector<ConstraintSet>;

  /// Includes information about
  ///   * function prototype (which is necessary to
  ///     ensure we're modeling the right function and casting values properly),
  ///   * approach to invalidation,
  ///   * a list of branches - a list of list of ranges -
  ///     A branch represents a path in the exploded graph of a function (which
  ///     is a tree). So, a branch is a series of assumptions. In other words,
  ///     branches represent split states and additional assumptions on top of
  ///     the splitting assumption.
  ///     For example, consider the branches in `isalpha(x)`
  ///       Branch 1)
  ///         x is in range ['A', 'Z'] or in ['a', 'z']
  ///         then the return value is not 0. (I.e. out-of-range [0, 0])
  ///       Branch 2)
  ///         x is out-of-range ['A', 'Z'] and out-of-range ['a', 'z']
  ///         then the return value is 0.
  ///   * a list of argument constraints, that must be true on every branch.
  ///     If these constraints are not satisfied that means a fatal error
  ///     usually resulting in undefined behaviour.
  struct Summary {
    const Signature Sign;
    const InvalidationKind InvalidationKd;
    Cases CaseConstraints;
    ConstraintSet ArgConstraints;

    // The function to which the summary applies. This is set after lookup and
    // match to the signature.
    const FunctionDecl *FD = nullptr;

    Summary(ArgTypes ArgTys, QualType RetTy, InvalidationKind InvalidationKd)
        : Sign(ArgTys, RetTy), InvalidationKd(InvalidationKd) {}

    // Create with empty signature.
    Summary(InvalidationKind InvalidationKd)
        : InvalidationKd(InvalidationKd) {}

    Summary &Case(ConstraintSet&& CS) {
      CaseConstraints.push_back(std::move(CS));
      return *this;
    }
    Summary &ArgConstraint(ValueConstraintPtr VC) {
      if (VC->skip())
        return *this;
      ArgConstraints.push_back(VC);
      return *this;
    }

    // Once we know the exact type of the function then do sanity check on all
    // the given constraints.
    bool validate(const FunctionDecl *FD) {
      for (const auto &Case : CaseConstraints)
        for (const ValueConstraintPtr &Constraint : Case)
          if (!Constraint->check(FD))
            return false;
      for (const ValueConstraintPtr &Constraint : ArgConstraints)
        if (!Constraint->check(FD))
          return false;
      this->FD = FD;
      return true;
    }
  };

  static QualType getArgType(const FunctionDecl *FD, ArgNo ArgN) {
    assert(FD && "Function must be set");
    QualType T = (ArgN == Ret)
                     ? FD->getReturnType().getCanonicalType()
                     : FD->getParamDecl(ArgN)->getType().getCanonicalType();
    return T;
  }

  // The map of all functions supported by the checker. It is initialized
  // lazily, and it doesn't change after initialization.
  using FunctionSummaryMapType = llvm::DenseMap<const FunctionDecl *, Summary>;
  mutable FunctionSummaryMapType FunctionSummaryMap;

  mutable std::unique_ptr<BugType> BT_InvalidArg;

  static SVal getArgSVal(const CallEvent &Call, ArgNo ArgN) {
    return ArgN == Ret ? Call.getReturnValue() : Call.getArgSVal(ArgN);
  }

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  bool evalCall(const CallEvent &Call, CheckerContext &C) const;

  enum CheckKind {
    CK_StdCLibraryFunctionArgsChecker,
    CK_StdCLibraryFunctionsTesterChecker,
    CK_NumCheckKinds
  };
  DefaultBool ChecksEnabled[CK_NumCheckKinds];
  CheckerNameRef CheckNames[CK_NumCheckKinds];

  bool DisplayLoadedSummaries = false;

private:
  Optional<Summary> findFunctionSummary(const FunctionDecl *FD,
                                        CheckerContext &C) const;
  Optional<Summary> findFunctionSummary(const CallEvent &Call,
                                        CheckerContext &C) const;

  void initFunctionSummaries(CheckerContext &C) const;

  void reportBug(const CallEvent &Call, ExplodedNode *N, const ValueConstraint* VC,
                 CheckerContext &C) const {
    if (!ChecksEnabled[CK_StdCLibraryFunctionArgsChecker])
      return;
    // TODO Add more detailed diagnostic.
    std::string Msg =
        std::string("Function argument constraint is not satisfied, ") +
        VC->getName().data() + ", ArgN: " + std::to_string(VC->getArgNo());
    if (!BT_InvalidArg)
      BT_InvalidArg = std::make_unique<BugType>(
          CheckNames[CK_StdCLibraryFunctionArgsChecker],
          "Unsatisfied argument constraints", categories::LogicError);
    auto R = std::make_unique<PathSensitiveBugReport>(*BT_InvalidArg, Msg, N);
    bugreporter::trackExpressionValue(N, Call.getArgExpr(VC->getArgNo()), *R);

    // Highlight the range of the argument that was violated.
    R->addRange(Call.getArgSourceRange(VC->getArgNo()));

    C.emitReport(std::move(R));
  }
};

const StdLibraryFunctionsChecker::ArgNo StdLibraryFunctionsChecker::Ret =
    std::numeric_limits<ArgNo>::max();

} // end of anonymous namespace

ProgramStateRef StdLibraryFunctionsChecker::RangeConstraint::applyAsOutOfRange(
    ProgramStateRef State, const CallEvent &Call,
    const Summary &Summary) const {

  ProgramStateManager &Mgr = State->getStateManager();
  SValBuilder &SVB = Mgr.getSValBuilder();
  BasicValueFactory &BVF = SVB.getBasicValueFactory();
  ConstraintManager &CM = Mgr.getConstraintManager();
  QualType T = getArgType(Summary.FD, getArgNo());
  SVal V = getArgSVal(Call, getArgNo());

  if (auto N = V.getAs<NonLoc>()) {
    const IntRangeVector &R = getRanges(Summary.FD, BVF);
    size_t E = R.size();
    for (size_t I = 0; I != E; ++I) {
      const llvm::APSInt &Min = BVF.getValue(R[I].first, T);
      const llvm::APSInt &Max = BVF.getValue(R[I].second, T);
      assert(Min <= Max);
      State = CM.assumeInclusiveRange(State, *N, Min, Max, false);
      if (!State)
        break;
    }
  }

  return State;
}

ProgramStateRef StdLibraryFunctionsChecker::RangeConstraint::applyAsWithinRange(
    ProgramStateRef State, const CallEvent &Call,
    const Summary &Summary) const {

  ProgramStateManager &Mgr = State->getStateManager();
  SValBuilder &SVB = Mgr.getSValBuilder();
  BasicValueFactory &BVF = SVB.getBasicValueFactory();
  ConstraintManager &CM = Mgr.getConstraintManager();
  QualType T = getArgType(Summary.FD, getArgNo());
  SVal V = getArgSVal(Call, getArgNo());

  // "WithinRange R" is treated as "outside [T_MIN, T_MAX] \ R".
  // We cut off [T_MIN, min(R) - 1] and [max(R) + 1, T_MAX] if necessary,
  // and then cut away all holes in R one by one.
  //
  // E.g. consider a range list R as [A, B] and [C, D]
  // -------+--------+------------------+------------+----------->
  //        A        B                  C            D
  // Then we assume that the value is not in [-inf, A - 1],
  // then not in [D + 1, +inf], then not in [B + 1, C - 1]
  if (auto N = V.getAs<NonLoc>()) {
    const IntRangeVector &R = getRanges(Summary.FD, BVF);
    size_t E = R.size();

    const llvm::APSInt &MinusInf = BVF.getMinValue(T);
    const llvm::APSInt &PlusInf = BVF.getMaxValue(T);

    const llvm::APSInt &Left = BVF.getValue(R[0].first - 1ULL, T);
    if (Left != PlusInf) {
      assert(MinusInf <= Left);
      State = CM.assumeInclusiveRange(State, *N, MinusInf, Left, false);
      if (!State)
        return nullptr;
    }

    const llvm::APSInt &Right = BVF.getValue(R[E - 1].second + 1ULL, T);
    if (Right != MinusInf) {
      assert(Right <= PlusInf);
      State = CM.assumeInclusiveRange(State, *N, Right, PlusInf, false);
      if (!State)
        return nullptr;
    }

    for (size_t I = 1; I != E; ++I) {
      const llvm::APSInt &Min = BVF.getValue(R[I - 1].second + 1ULL, T);
      const llvm::APSInt &Max = BVF.getValue(R[I].first - 1ULL, T);
      if (Min <= Max) {
        State = CM.assumeInclusiveRange(State, *N, Min, Max, false);
        if (!State)
          return nullptr;
      }
    }
  }

  return State;
}

ProgramStateRef StdLibraryFunctionsChecker::ComparisonConstraint::apply(
    ProgramStateRef State, const CallEvent &Call, const Summary &Summary,
    CheckerContext &C) const {

  ProgramStateManager &Mgr = State->getStateManager();
  SValBuilder &SVB = Mgr.getSValBuilder();
  QualType CondT = SVB.getConditionType();
  QualType T = getArgType(Summary.FD, getArgNo());
  SVal V = getArgSVal(Call, getArgNo());

  BinaryOperator::Opcode Op = getOpcode();
  ArgNo OtherArg = getOtherArgNo();
  SVal OtherV = getArgSVal(Call, OtherArg);
  QualType OtherT = getArgType(Summary.FD, OtherArg);
  // Note: we avoid integral promotion for comparison.
  OtherV = SVB.evalCast(OtherV, T, OtherT);
  if (auto CompV = SVB.evalBinOp(State, Op, V, OtherV, CondT)
                       .getAs<DefinedOrUnknownSVal>())
    State = State->assume(*CompV, true);
  return State;
}

void StdLibraryFunctionsChecker::checkPreCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  ++NumCall;
  Optional<Summary> FoundSummary = findFunctionSummary(Call, C);
  if (!FoundSummary)
    return;
  ++NumFoundSummary;

  const Summary &Summary = *FoundSummary;
  ProgramStateRef State = C.getState();

  ProgramStateRef NewState = State;
  for (const ValueConstraintPtr& VC : Summary.ArgConstraints) {
    assert(VC->getArgNo() != Ret &&
           "Arg constraint should not refer to the return value");
    ProgramStateRef SuccessSt = VC->apply(NewState, Call, Summary, C);
    ProgramStateRef FailureSt = VC->negate()->apply(NewState, Call, Summary, C);
    // The argument constraint is not satisfied.
    if (FailureSt && !SuccessSt) {
      ++NumArgConstraintViolated;
      if (ExplodedNode *N = C.generateErrorNode(NewState))
        reportBug(Call, N, VC.get(), C);
      break;
    } else {
      // We will apply the constraint even if we cannot reason about the
      // argument. This means both SuccessSt and FailureSt can be true. If we
      // weren't applying the constraint that would mean that symbolic
      // execution continues on a code whose behaviour is undefined.
      assert(SuccessSt);
      NewState = SuccessSt;
    }
  }
  if (NewState && NewState != State) {
    ++NumArgConstrained;
    C.addTransition(NewState);
  }
}

void StdLibraryFunctionsChecker::checkPostCall(const CallEvent &Call,
                                               CheckerContext &C) const {
  Optional<Summary> FoundSummary = findFunctionSummary(Call, C);
  if (!FoundSummary)
    return;

  // Now apply the constraints.
  const Summary &Summary = *FoundSummary;
  ProgramStateRef State = C.getState();

  // Apply case/branch specifications.
  for (const auto &VRS : Summary.CaseConstraints) {
    ProgramStateRef NewState = State;
    for (const auto &VR: VRS) {
      NewState = VR->apply(NewState, Call, Summary, C);
      if (!NewState)
        break;
    }

    if (NewState && NewState != State) {
      ++NumCaseApplied;
      C.addTransition(NewState);
    }
  }
}

bool StdLibraryFunctionsChecker::evalCall(const CallEvent &Call,
                                          CheckerContext &C) const {
  Optional<Summary> FoundSummary = findFunctionSummary(Call, C);
  if (!FoundSummary)
    return false;

  const Summary &Summary = *FoundSummary;
  switch (Summary.InvalidationKd) {
  case EvalCallAsPure: {
    ProgramStateRef State = C.getState();
    const LocationContext *LC = C.getLocationContext();
    const auto *CE = cast_or_null<CallExpr>(Call.getOriginExpr());
    SVal V = C.getSValBuilder().conjureSymbolVal(
        CE, LC, CE->getType().getCanonicalType(), C.blockCount());
    State = State->BindExpr(CE, LC, V);
    C.addTransition(State);
    return true;
  }
  case NoEvalCall:
    // Summary tells us to avoid performing eval::Call. The function is possibly
    // evaluated by another checker, or evaluated conservatively.
    return false;
  }
  llvm_unreachable("Unknown invalidation kind!");
}

bool StdLibraryFunctionsChecker::Signature::matches(
    const FunctionDecl *FD) const {
  // Empty matches everything.
  if (empty())
    return true;

  // Check number of arguments:
  if (FD->param_size() != ArgTys.size())
    return false;

  // Check return type.
  if (!isIrrelevant(RetTy))
    if (RetTy != FD->getReturnType().getCanonicalType())
      return false;

  // Check argument types.
  for (size_t I = 0, E = ArgTys.size(); I != E; ++I) {
    QualType ArgTy = ArgTys[I];
    if (isIrrelevant(ArgTy))
      continue;
    if (ArgTy != FD->getParamDecl(I)->getType().getCanonicalType())
      return false;
  }

  return true;
}

Optional<StdLibraryFunctionsChecker::Summary>
StdLibraryFunctionsChecker::findFunctionSummary(const FunctionDecl *FD,
                                                CheckerContext &C) const {
  if (!FD)
    return None;

  initFunctionSummaries(C);

  auto FSMI = FunctionSummaryMap.find(FD->getCanonicalDecl());
  if (FSMI == FunctionSummaryMap.end())
    return None;
  return FSMI->second;
}

Optional<StdLibraryFunctionsChecker::Summary>
StdLibraryFunctionsChecker::findFunctionSummary(const CallEvent &Call,
                                                CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return None;
  return findFunctionSummary(FD, C);
}

llvm::Optional<const FunctionDecl *>
lookupGlobalCFunction(StringRef Name, const ASTContext &ACtx) {
  IdentifierInfo &II = ACtx.Idents.get(Name);
  auto LookupRes = ACtx.getTranslationUnitDecl()->lookup(&II);
  if (LookupRes.size() == 0)
    return None;

  assert(LookupRes.size() == 1 && "In C, identifiers should be unique");
  Decl *D = LookupRes.front()->getCanonicalDecl();
  auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return None;
  return FD->getCanonicalDecl();
}

void StdLibraryFunctionsChecker::initFunctionSummaries(
    CheckerContext &C) const {
  if (!FunctionSummaryMap.empty())
    return;

  SValBuilder &SVB = C.getSValBuilder();
  BasicValueFactory &BVF = SVB.getBasicValueFactory();
  const ASTContext &ACtx = BVF.getContext();

  // These types are useful for writing specifications quickly,
  // New specifications should probably introduce more types.
  // Some types are hard to obtain from the AST, eg. "ssize_t".
  // In such cases it should be possible to provide multiple variants
  // of function summary for common cases (eg. ssize_t could be int or long
  // or long long, so three summary variants would be enough).
  // Of course, function variants are also useful for C++ overloads.
  // const QualType CharTy = ACtx.CharTy;
  const QualType WCharTy = ACtx.WideCharTy;
  const QualType IntTy = ACtx.IntTy;
  const QualType LongTy = ACtx.LongTy;
  const QualType UnsignedLongTy = ACtx.UnsignedLongTy;
  const QualType LongLongTy = ACtx.LongLongTy;
  const QualType SizeTy = ACtx.getSizeType();
  const QualType VoidTy = ACtx.VoidTy;
  const QualType VoidPtrTy = ACtx.VoidPtrTy; // void *
  const QualType VoidPtrRestrictTy =
      ACtx.getRestrictType(VoidPtrTy); // void *restrict
  const QualType ConstVoidPtrTy =
      ACtx.getPointerType(ACtx.VoidTy.withConst()); // const void *
  const QualType CharPtrTy = ACtx.getPointerType(ACtx.CharTy); // char *
  const QualType ConstCharPtrTy =
      ACtx.getPointerType(ACtx.CharTy.withConst()); // const char *
  const QualType WCharPtrTy = ACtx.getPointerType(WCharTy); // wchar_t *
  const QualType ConstVoidPtrRestrictTy =
      ACtx.getRestrictType(ConstVoidPtrTy); // const void *restrict

  const RangeInt IntMax = BVF.getMaxValue(IntTy).getLimitedValue();
  const RangeInt IntMin = BVF.getMinValue(IntTy).getLimitedValue();
  const RangeInt LongMax = BVF.getMaxValue(LongTy).getLimitedValue();
  const RangeInt LongLongMax = BVF.getMaxValue(LongLongTy).getLimitedValue();

  // Set UCharRangeMax to min of int or uchar maximum value.
  // The C standard states that the arguments of functions like isalpha must
  // be representable as an unsigned char. Their type is 'int', so the max
  // value of the argument should be min(UCharMax, IntMax). This just happen
  // to be true for commonly used and well tested instruction set
  // architectures, but not for others.
  const RangeInt UCharRangeMax =
      std::min(BVF.getMaxValue(ACtx.UnsignedCharTy).getLimitedValue(), IntMax);

  // The platform dependent value of EOF.
  // Try our best to parse this from the Preprocessor, otherwise fallback to -1.
  const auto EOFv = [&C]() -> RangeInt {
    if (const llvm::Optional<int> OptInt =
            tryExpandAsInteger("EOF", C.getPreprocessor()))
      return *OptInt;
    return -1;
  }();

  // Auxiliary class to aid adding summaries to the summary map.
  struct AddToFunctionSummaryMap {
    const ASTContext &ACtx;
    FunctionSummaryMapType &Map;
    bool DisplayLoadedSummaries;
    AddToFunctionSummaryMap(const ASTContext &ACtx, FunctionSummaryMapType &FSM,
                            bool DisplayLoadedSummaries)
        : ACtx(ACtx), Map(FSM), DisplayLoadedSummaries(DisplayLoadedSummaries) {
    }
    // Add a summary to a FunctionDecl found by lookup. The lookup is performed
    // by the given Name, and in the global scope. The summary will be attached
    // to the found FunctionDecl only if the signatures match.
    void operator()(StringRef Name, Summary S) {
      IdentifierInfo &II = ACtx.Idents.get(Name);
      auto LookupRes = ACtx.getTranslationUnitDecl()->lookup(&II);
      if (LookupRes.size() == 0)
        return;
      // FunctionDecls.
      SmallVector<FunctionDecl *, 2> FDs;
      for (Decl *D : LookupRes) {
        if (auto *FD = dyn_cast<FunctionDecl>(D))
          FDs.push_back(FD);
      }
      // Empty signatures should be used only only without name overloading.
      if (FDs.size() > 1 && S.Sign.empty())
        return;
      for (FunctionDecl *FD : FDs) {
        if (S.Sign.matches(FD) && S.validate(FD)) {
          auto Res = Map.insert({FD->getCanonicalDecl(), S});
          assert(Res.second && "Function already has a summary set!");
          (void)Res;
          if (DisplayLoadedSummaries)
            llvm::errs() << "Loaded summary for " << Name << "\n";
          return;
        }
      }
    }
    // Add several summaries for the given name.
    void operator()(StringRef Name, const std::vector<Summary> &Summaries) {
      for (const Summary &S : Summaries)
        operator()(Name, S);
    }

    // Add the same summary for different names.
    void operator()(std::vector<StringRef> Names, Summary S) {
      for (StringRef Name : Names)
        operator()(Name, S);
    }
  } addToFunctionSummaryMap(ACtx, FunctionSummaryMap, DisplayLoadedSummaries);

  // We are finally ready to define specifications for all supported functions.
  //
  // The signature needs to have the correct number of arguments.
  // However, we insert `Irrelevant' when the type is insignificant.
  //
  // Argument ranges should always cover all variants. If return value
  // is completely unknown, omit it from the respective range set.
  //
  // All types in the spec need to be canonical.
  //
  // Every item in the list of range sets represents a particular
  // execution path the analyzer would need to explore once
  // the call is modeled - a new program state is constructed
  // for every range set, and each range line in the range set
  // corresponds to a specific constraint within this state.
  //
  // Upon comparing to another argument, the other argument is casted
  // to the current argument's type. This avoids proper promotion but
  // seems useful. For example, read() receives size_t argument,
  // and its return value, which is of type ssize_t, cannot be greater
  // than this argument. If we made a promotion, and the size argument
  // is equal to, say, 10, then we'd impose a range of [0, 10] on the
  // return value, however the correct range is [-1, 10].
  //
  // Please update the list of functions in the header after editing!

  // Below are helpers functions to create the summaries.
  auto ArgumentCondition = [](ArgNo ArgN, RangeKind Kind,
                             LazyIntRangeVector Ranges) {
    return std::make_shared<RangeConstraint>(ArgN, Kind, Ranges);
  };
  auto BufferSize = [](auto ...Args) {
    return std::make_shared<BufferSizeConstraint>(Args...);
  };
  struct {
    auto operator()(RangeKind Kind, LazyIntRangeVector Ranges) {
      return std::make_shared<RangeConstraint>(Ret, Kind, Ranges);
    }
    auto operator()(BinaryOperator::Opcode Op, ArgNo OtherArgN) {
      return std::make_shared<ComparisonConstraint>(Ret, Op, OtherArgN);
    }
  } ReturnValueCondition;
  auto Range = [](LazyRangeInt b, LazyRangeInt e) {
    return LazyIntRangeVector{std::pair<LazyRangeInt, LazyRangeInt>{b, e}};
  };
  auto SingleValue = [](LazyRangeInt v) {
    return LazyIntRangeVector{std::pair<LazyRangeInt, LazyRangeInt>{v, v}};
  };
  auto LessThanOrEq = BO_LE;
  auto NotNull = [&](ArgNo ArgN) {
    return std::make_shared<NotNullConstraint>(ArgN);
  };

  using RetType = QualType;

  // The isascii() family of functions.
  // The behavior is undefined if the value of the argument is not
  // representable as unsigned char or is not equal to EOF. See e.g. C99
  // 7.4.1.2 The isalpha function (p: 181-182).
  addToFunctionSummaryMap(
      "isalnum",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          // Boils down to isupper() or islower() or isdigit().
          .Case({ArgumentCondition(0U, WithinRange,
                                   {{'0', '9'}, {'A', 'Z'}, {'a', 'z'}}),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          // The locale-specific range.
          // No post-condition. We are completely unaware of
          // locale-specific return values.
          .Case({ArgumentCondition(0U, WithinRange, {{128, UCharRangeMax}})})
          .Case(
              {ArgumentCondition(
                   0U, OutOfRange,
                   {{'0', '9'}, {'A', 'Z'}, {'a', 'z'}, {128, UCharRangeMax}}),
               ReturnValueCondition(WithinRange, SingleValue(0))})
          .ArgConstraint(ArgumentCondition(
              0U, WithinRange, {{EOFv, EOFv}, {0, UCharRangeMax}})));
  addToFunctionSummaryMap(
      "isalpha",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(0U, WithinRange, {{'A', 'Z'}, {'a', 'z'}}),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          // The locale-specific range.
          .Case({ArgumentCondition(0U, WithinRange, {{128, UCharRangeMax}})})
          .Case({ArgumentCondition(
                     0U, OutOfRange,
                     {{'A', 'Z'}, {'a', 'z'}, {128, UCharRangeMax}}),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "isascii",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(0U, WithinRange, Range(0, 127)),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          .Case({ArgumentCondition(0U, OutOfRange, Range(0, 127)),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "isblank",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(0U, WithinRange, {{'\t', '\t'}, {' ', ' '}}),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          .Case({ArgumentCondition(0U, OutOfRange, {{'\t', '\t'}, {' ', ' '}}),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "iscntrl",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(0U, WithinRange, {{0, 32}, {127, 127}}),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          .Case({ArgumentCondition(0U, OutOfRange, {{0, 32}, {127, 127}}),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "isdigit",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(0U, WithinRange, Range('0', '9')),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          .Case({ArgumentCondition(0U, OutOfRange, Range('0', '9')),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "isgraph",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(0U, WithinRange, Range(33, 126)),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          .Case({ArgumentCondition(0U, OutOfRange, Range(33, 126)),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "islower",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          // Is certainly lowercase.
          .Case({ArgumentCondition(0U, WithinRange, Range('a', 'z')),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          // Is ascii but not lowercase.
          .Case({ArgumentCondition(0U, WithinRange, Range(0, 127)),
                 ArgumentCondition(0U, OutOfRange, Range('a', 'z')),
                 ReturnValueCondition(WithinRange, SingleValue(0))})
          // The locale-specific range.
          .Case({ArgumentCondition(0U, WithinRange, {{128, UCharRangeMax}})})
          // Is not an unsigned char.
          .Case({ArgumentCondition(0U, OutOfRange, Range(0, UCharRangeMax)),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "isprint",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(0U, WithinRange, Range(32, 126)),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          .Case({ArgumentCondition(0U, OutOfRange, Range(32, 126)),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "ispunct",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(
                     0U, WithinRange,
                     {{'!', '/'}, {':', '@'}, {'[', '`'}, {'{', '~'}}),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          .Case({ArgumentCondition(
                     0U, OutOfRange,
                     {{'!', '/'}, {':', '@'}, {'[', '`'}, {'{', '~'}}),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "isspace",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          // Space, '\f', '\n', '\r', '\t', '\v'.
          .Case({ArgumentCondition(0U, WithinRange, {{9, 13}, {' ', ' '}}),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          // The locale-specific range.
          .Case({ArgumentCondition(0U, WithinRange, {{128, UCharRangeMax}})})
          .Case({ArgumentCondition(0U, OutOfRange,
                                   {{9, 13}, {' ', ' '}, {128, UCharRangeMax}}),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "isupper",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          // Is certainly uppercase.
          .Case({ArgumentCondition(0U, WithinRange, Range('A', 'Z')),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          // The locale-specific range.
          .Case({ArgumentCondition(0U, WithinRange, {{128, UCharRangeMax}})})
          // Other.
          .Case({ArgumentCondition(0U, OutOfRange,
                                   {{'A', 'Z'}, {128, UCharRangeMax}}),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));
  addToFunctionSummaryMap(
      "isxdigit",
      Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
          .Case({ArgumentCondition(0U, WithinRange,
                                   {{'0', '9'}, {'A', 'F'}, {'a', 'f'}}),
                 ReturnValueCondition(OutOfRange, SingleValue(0))})
          .Case({ArgumentCondition(0U, OutOfRange,
                                   {{'0', '9'}, {'A', 'F'}, {'a', 'f'}}),
                 ReturnValueCondition(WithinRange, SingleValue(0))}));

  // The getc() family of functions that returns either a char or an EOF.
  auto Getc = Summary(ArgTypes{Irrelevant}, RetType{IntTy}, NoEvalCall)
        .Case({ReturnValueCondition(WithinRange,
                                    {{EOFv, EOFv}, {0, UCharRangeMax}})});
  addToFunctionSummaryMap("getc", Getc);
  addToFunctionSummaryMap("fgetc", Getc);
  addToFunctionSummaryMap(
      "getchar", Summary(ArgTypes{}, RetType{IntTy}, NoEvalCall)
                     .Case({ReturnValueCondition(
                         WithinRange, {{EOFv, EOFv}, {0, UCharRangeMax}})}));

  // read()-like functions that never return more than buffer size.
  auto Read = Summary(NoEvalCall)
                  .Case({ReturnValueCondition(LessThanOrEq, ArgNo(2)),
                         ReturnValueCondition(WithinRange, Range(-1, Max))});
  addToFunctionSummaryMap("read", Read);
  addToFunctionSummaryMap("write", Read);
  auto Fread = Summary(NoEvalCall)
                   .Case({
                       ReturnValueCondition(LessThanOrEq, ArgNo(2)),
                   })
                   .ArgConstraint(NotNull(ArgNo(0)));
  addToFunctionSummaryMap("fread", Fread);
  addToFunctionSummaryMap("fwrite", Fread);

  // getline()-like functions either fail or read at least the delimiter.
  auto Getline = Summary(NoEvalCall)
        .Case({ReturnValueCondition(WithinRange, {{-1, -1}, {1, Max}})});
  addToFunctionSummaryMap("getline", Getline);
  addToFunctionSummaryMap("getdelim", Getline);

  // int fprintf(FILE *stream, const char *format, ...);
  addToFunctionSummaryMap(
      "fprintf",
      Summary(ArgTypes{Irrelevant, ConstCharPtrTy}, RetType{IntTy}, NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(NotNull(ArgNo(1))));

  // size_t strcspn(const char *cs, const char *ct);
  addToFunctionSummaryMap("strcspn",
                          Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy},
                                  RetType{SizeTy}, EvalCallAsPure)
                              // TODO .ArgConstraint(NullTerminated(ArgNo(0)))
                              // TODO .ArgConstraint(NullTerminated(ArgNo(1)))
                              .ArgConstraint(NotNull(ArgNo(0)))
                              .ArgConstraint(NotNull(ArgNo(1))));

  // void qsort(void *base, size_t n, size_t size,
  //            int (*cmp)(const void *, const void *));
  addToFunctionSummaryMap(
      "qsort",
      Summary(ArgTypes{VoidPtrTy, SizeTy, SizeTy, Irrelevant}, RetType{VoidTy},
              NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(NotNull(ArgNo(3)))
          //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, SizeMax)))
          //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, SizeMax)))
          );

  // int abs(int j);    intmax_t imaxabs(intmax_t n);    double fabs(double x);
  // double complex cabs(double complex z);    long int labs(long int x); long
  // long int llabs(long long int x);
  addToFunctionSummaryMap(
      "abs", Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
                 .Case({ArgumentCondition(0, WithinRange, SingleValue(0)),
                        ReturnValueCondition(WithinRange, SingleValue(0))})
                 .Case({ArgumentCondition(0, WithinRange, Range(1, IntMax)),
                        ReturnValueCondition(WithinRange, Range(IntMin, -1))})
                 .Case({ArgumentCondition(0, WithinRange, Range(IntMin, -1)),
                        ReturnValueCondition(WithinRange, Range(1, IntMax))}));

  // double sqrt(double x);
  // addToFunctionSummaryMap("sqrt",
  // Summary(ArgTypes{}, RetType{}, EvalCallAsPure)
  //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0.0:)))
  //);

  // int mbtowc(wchar_t* pwc, const char* pmb, size_t max);
  addToFunctionSummaryMap(
      "mbtowc",
      Summary(ArgTypes{WCharPtrTy, ConstCharPtrTy, SizeTy}, RetType{IntTy},
              NoEvalCall)
          //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, SizeMax)))
          );

  // struct tm * localtime(const time_t *tp);
  addToFunctionSummaryMap("localtime", Summary(ArgTypes{Irrelevant},
                                               RetType{Irrelevant}, NoEvalCall)
                                           .ArgConstraint(NotNull(ArgNo(0))));

  // void *memchr(const void *s, int c, size_t n);
  addToFunctionSummaryMap(
      "memchr",
      Summary(ArgTypes{ConstVoidPtrTy, IntTy, SizeTy}, RetType{VoidPtrTy},
              EvalCallAsPure)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(BufferSize(0, 2))
          .ArgConstraint(
              ArgumentCondition(1, WithinRange, Range(0, UCharRangeMax)))
          //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, SizeMax)))
          );

  // void* bsearch(const void* key, const void* base, size_t num, size_t size,
  // int(*compar)(const void*,const void*));
  addToFunctionSummaryMap(
      "bsearch",
      Summary(ArgTypes{ConstVoidPtrTy, ConstVoidPtrTy, SizeTy, SizeTy},
              RetType{VoidPtrTy}, EvalCallAsPure)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(NotNull(ArgNo(1)))
          //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, SizeMax)))
          //.ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, SizeMax)))
          .ArgConstraint(NotNull(ArgNo(4))));

  // int fputc(int c, FILE *stream);
  // int putc(int c, FILE *stream);
  addToFunctionSummaryMap(
      {"fputc", "putc"},
      Summary(ArgTypes{IntTy, Irrelevant}, RetType{IntTy}, NoEvalCall)
          .ArgConstraint(
              ArgumentCondition(0, WithinRange, Range(0, UCharRangeMax)))
          .ArgConstraint(NotNull(ArgNo(1))));

  // void *reallocarray(void *ptr, size_t nmemb, size_t size);
  addToFunctionSummaryMap(
      "reallocarray",
      Summary(ArgTypes{VoidPtrTy, SizeTy, SizeTy}, RetType{VoidPtrTy},
              NoEvalCall)
          //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, SizeMax)))
          //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, SizeMax)))
          );

  // size_t strftime(char *s, size_t max, const char *fmt, const struct tm *p);
  addToFunctionSummaryMap(
      "strftime",
      Summary(ArgTypes{CharPtrTy, SizeTy, ConstCharPtrTy, Irrelevant},
              RetType{SizeTy}, NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, SizeMax)))
          .ArgConstraint(NotNull(ArgNo(2)))
          .ArgConstraint(NotNull(ArgNo(3))));

  // char* strstr(const char *s1, const char *s2);
  addToFunctionSummaryMap("strstr",
                          Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy},
                                  RetType{CharPtrTy}, NoEvalCall)
                              .ArgConstraint(NotNull(ArgNo(0)))
                              .ArgConstraint(NotNull(ArgNo(1))));

  // size_t strspn(const char *cs, const char *ct);
  addToFunctionSummaryMap("strspn",
                          Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy},
                                  RetType{SizeTy}, NoEvalCall)
                              .ArgConstraint(NotNull(ArgNo(0)))
                              .ArgConstraint(NotNull(ArgNo(1))));

  auto Strtol = [&](RetType R) {
    return Summary(ArgTypes{ConstCharPtrTy, Irrelevant, IntTy}, RetType{R},
                   NoEvalCall)
        .ArgConstraint(NotNull(ArgNo(0)))
        .ArgConstraint(ArgumentCondition(2, WithinRange, {{0, 0}, {2, 36}}));
  };
  // long strtol(const char *s, char **endp, int base);
  addToFunctionSummaryMap("strtol", Strtol(LongTy));
  // unsigned long strtoul(const char *s, char **endp, int base);
  addToFunctionSummaryMap("strtoul", Strtol(UnsignedLongTy));
  // long long strtoll(const char *s, char **endp, int base);
  addToFunctionSummaryMap("strtoll", Strtol(LongLongTy));

  // char * ctime(const time_t *tp);
  addToFunctionSummaryMap(
      "ctime", Summary(ArgTypes{Irrelevant}, RetType{CharPtrTy}, NoEvalCall)
                   .ArgConstraint(NotNull(ArgNo(0))));

  // int fputs(const char *string, FILE* stream);
  addToFunctionSummaryMap("fputs", Summary(ArgTypes{ConstCharPtrTy, Irrelevant},
                                           RetType{IntTy}, NoEvalCall)
                                       .ArgConstraint(NotNull(ArgNo(0)))
                                       .ArgConstraint(NotNull(ArgNo(1))));

  // char * getenv(const char *name);
  addToFunctionSummaryMap(
      "getenv", Summary(ArgTypes{Irrelevant}, RetType{CharPtrTy}, NoEvalCall)
                    .ArgConstraint(NotNull(ArgNo(0))));

  // char * strchr(const char *cs, int c);
  // char * strrchr(const char * str, int character);
  addToFunctionSummaryMap(
      {"strchr", "strrchr"},
      Summary(ArgTypes{ConstCharPtrTy, IntTy}, RetType{CharPtrTy}, NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(
              ArgumentCondition(1, WithinRange, Range(0, UCharRangeMax))));

  // int tolower(int c);
  // int toupper(int c);
  addToFunctionSummaryMap(
      {"tolower", "toupper"},
      Summary(ArgTypes{}, RetType{}, NoEvalCall)
          .Case({ReturnValueCondition(WithinRange,
                                      {{EOFv, EOFv}, {0, UCharRangeMax}})})
          .ArgConstraint(ArgumentCondition(
              0, WithinRange, {{EOFv, EOFv}, {0, UCharRangeMax}})));

  // POSIX

  // long a64l(const char *str64);
  addToFunctionSummaryMap("a64l",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *l64a(long value);        The behavior of l64a() is undefined when
  // value is negative.
  addToFunctionSummaryMap("l64a", Summary(NoEvalCall)
                                      .ArgConstraint(ArgumentCondition(
                                          0, WithinRange, Range(0, Max))));

  // int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  addToFunctionSummaryMap(
      "accept",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int access(const char *pathname, int amode);
  addToFunctionSummaryMap("access",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int bind(int socket, const struct sockaddr *address, socklen_t
  // address_len);
  addToFunctionSummaryMap(
      "bind",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          // FIXME The below param is actually a transparent union in C
          // (__CONST_SOCKADDR_ARG). We should be able to handle transparent
          // union of pointers as a pointer. See the attribute
          // __transparent_union__ .
          //.ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(BufferSize(1, 2))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // int listen(int sockfd, int backlog);
  addToFunctionSummaryMap(
      "listen",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  addToFunctionSummaryMap(
      "getpeername",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          // FIXME The below param is actually a transparent union in C
          // (__CONST_SOCKADDR_ARG). We should be able to handle transparent
          // union of pointers as a pointer. See the attribute
          // __transparent_union__ .
          //.ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(NotNull(ArgNo(2))));

  // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  addToFunctionSummaryMap(
      "getsockname",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          // FIXME The below param is actually a transparent union in C
          // (__CONST_SOCKADDR_ARG). We should be able to handle transparent
          // union of pointers as a pointer. See the attribute
          // __transparent_union__ .
          //.ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(NotNull(ArgNo(2))));

  // int connect(int socket, const struct sockaddr *address, socklen_t
  // address_len);
  addToFunctionSummaryMap("connect", Summary(NoEvalCall)
                                         .ArgConstraint(ArgumentCondition(
                                             0, WithinRange, Range(0, Max)))
          // FIXME The below param is actually a transparent union in C
          // (__CONST_SOCKADDR_ARG). We should be able to handle transparent
          // union of pointers as a pointer. See the attribute
          // __transparent_union__ .
                                         //.ArgConstraint(NotNull(ArgNo(1)))
                                         );

  // int dup(int fildes);   char *strdup(const char *s);    char *strndup(const
  // char *s, size_t n);    wchar_t *wcsdup(const wchar_t *s);
  addToFunctionSummaryMap("dup", Summary(NoEvalCall)
                                     .ArgConstraint(ArgumentCondition(
                                         0, WithinRange, Range(0, Max))));

  // int dup2(int fildes1, int filedes2);
  addToFunctionSummaryMap(
      "dup2",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max))));

  // void FD_CLR(int fd, fd_set *set);
  addToFunctionSummaryMap("FD_CLR", Summary(NoEvalCall)
                                        .ArgConstraint(ArgumentCondition(
                                            0, WithinRange, Range(0, Max)))
                                        .ArgConstraint(NotNull(ArgNo(1))));

  // int FD_ISSET(int fd, fd_set *set);
  addToFunctionSummaryMap(
      "FD_ISSET",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          .ArgConstraint(NotNull(ArgNo(1))));

  // void FD_SET(int fd, fd_set *set);
  addToFunctionSummaryMap("FD_SET", Summary(NoEvalCall)
                                        .ArgConstraint(ArgumentCondition(
                                            0, WithinRange, Range(0, Max)))
                                        .ArgConstraint(NotNull(ArgNo(1))));

  // void FD_ZERO(fd_set *set);
  addToFunctionSummaryMap("FD_ZERO",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int fdatasync(int fildes);
  addToFunctionSummaryMap(
      "fdatasync",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int fnmatch(const char *pattern, const char *string, int flags);
  addToFunctionSummaryMap("fnmatch", Summary(EvalCallAsPure)
                                         .ArgConstraint(NotNull(ArgNo(0)))
                                         .ArgConstraint(NotNull(ArgNo(1))));

  // int fsync(int fildes);
  addToFunctionSummaryMap("fsync", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // int truncate(const char *path, off_t length);    int ftruncate(int fd,
  // off_t length);
  addToFunctionSummaryMap("truncate",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int flock(int fd, int operation);
  addToFunctionSummaryMap("flock", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // int lockf(int fd, int cmd, off_t len);
  addToFunctionSummaryMap("lockf", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // int symlinkat(const char *oldpath, int newdirfd, const char *newpath);
  addToFunctionSummaryMap("symlinkat", Summary(NoEvalCall)
                                           .ArgConstraint(NotNull(ArgNo(0)))
                                           .ArgConstraint(NotNull(ArgNo(2))));

  // int symlink(const char *oldpath, const char *newpath);
  addToFunctionSummaryMap("symlink", Summary(NoEvalCall)
                                         .ArgConstraint(NotNull(ArgNo(0)))
                                         .ArgConstraint(NotNull(ArgNo(1))));

  // void *dlopen(const char *file, int mode);    int open(const char *pathname,
  // int flags)    int open(const char *pathname, int flags, mode_t mode); FILE
  // *popen(const char *command, const char *type);    FILE *fdopen(int fd,
  // const char *mode);    mqd_t mq_open(const char *name, int oflag, ...); DBM
  // *dbm_open(const char *file, int open_flags, mode_t file_mode);    nl_catd
  // catopen(const char *name, int oflag);
  addToFunctionSummaryMap("open",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int openat(int dirfd, const char *pathname, int flags);    int openat(int
  // dirfd, const char *pathname, int flags, mode_t mode);
  addToFunctionSummaryMap("openat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int creat(const char *pathname, mode_t mode);
  addToFunctionSummaryMap("creat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // unsigned int sleep(unsigned int seconds);    int usleep(useconds_t
  // useconds); The obsolescent function 'usleep' is called. POSIX.1-2001
  // declares usleep() function obsolescent and POSIX.1-2008 removes it. It is
  // recommended that new applications use the 'nanosleep' or 'setitimer'
  // function.</warn>   int nanosleep(const struct timespec *rqtp, struct
  // timespec *rmtp);
  addToFunctionSummaryMap("sleep", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // int usleep(useconds_t useconds); The obsolescent function 'usleep' is
  // called. POSIX.1-2001 declares usleep() function obsolescent and
  // POSIX.1-2008 removes it. It is recommended that new applications use the
  // 'nanosleep' or 'setitimer' function.</warn>
  addToFunctionSummaryMap("usleep", Summary(NoEvalCall)
                                        .ArgConstraint(ArgumentCondition(
                                            0, WithinRange, Range(0, 1000000))));

  // int dirfd(DIR *dirp);
  addToFunctionSummaryMap("dirfd",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int faccessat(int dirfd, const char *pathname, int mode, int flags);
  addToFunctionSummaryMap("faccessat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // unsigned int alarm(unsigned int seconds);    useconds_t ualarm(useconds_t
  // useconds, useconds_t interval);
  addToFunctionSummaryMap("alarm", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // struct rpcent *getrpcbyname(char *name);
  addToFunctionSummaryMap("getrpcbyname",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct protoent *getprotobyname(const char *name);
  addToFunctionSummaryMap("getprotobyname",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct servent *getservbyname(const char *name, const char *proto);
  addToFunctionSummaryMap("getservbyname",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct netent *getnetbyname(const char *name);
  addToFunctionSummaryMap("getnetbyname",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct hostent *gethostbyname(const char *name);
  addToFunctionSummaryMap("gethostbyname",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct hostent *gethostbyname2(const char *name, int af);
  addToFunctionSummaryMap("gethostbyname2",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
  addToFunctionSummaryMap("gethostbyaddr",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int brk(void *addr);    void *sbrk(intptr_t incr);
  addToFunctionSummaryMap("brk",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int closedir(DIR *dir);
  addToFunctionSummaryMap("closedir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *strfry(char *string);
  addToFunctionSummaryMap("strfry",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *strsep(char **stringp, const char *delim);
  addToFunctionSummaryMap("strsep", Summary(NoEvalCall)
                                        .ArgConstraint(NotNull(ArgNo(0)))
                                        .ArgConstraint(NotNull(ArgNo(1))));

  // char *strdup(const char *s);
  addToFunctionSummaryMap("strdup",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *strndup(const char *s, size_t n);
  addToFunctionSummaryMap(
      "strndup",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max))));

  // wchar_t *wcsdup(const wchar_t *s);
  addToFunctionSummaryMap("wcsdup",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int mkstemp(char *template);
  addToFunctionSummaryMap("mkstemp",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *mkdtemp(char *template);
  addToFunctionSummaryMap("mkdtemp",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *mktemp(char *template);
  addToFunctionSummaryMap("mktemp",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *getcwd(char *buf, size_t size);
  addToFunctionSummaryMap(
      "getcwd",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max))));

  // int mkdir(const char *pathname, mode_t mode);
  addToFunctionSummaryMap("mkdir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int mknod(const char *pathname, mode_t mode, dev_t dev);
  addToFunctionSummaryMap("mknod",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
  addToFunctionSummaryMap("mknodat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int mkdirat(int dirfd, const char *pathname, mode_t mode);
  addToFunctionSummaryMap("mkdirat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
  addToFunctionSummaryMap("fchmodat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int
  // flags);
  addToFunctionSummaryMap("fchownat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int rmdir(const char *pathname);
  addToFunctionSummaryMap("rmdir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int chdir(const char *path);
  addToFunctionSummaryMap("chdir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int chroot(const char *path);
  addToFunctionSummaryMap("chroot",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int symlink(const char *oldpath, const char *newpath);    int link(const
  // char *oldpath, const char *newpath);    int unlink(const char *pathname);
  // int mq_unlink(const char *name);    ssize_t readlink(const char *path, char
  // *buf, size_t bufsiz);
  addToFunctionSummaryMap("link", Summary(NoEvalCall)
                                      .ArgConstraint(NotNull(ArgNo(0)))
                                      .ArgConstraint(NotNull(ArgNo(1))));

  // int symlinkat(const char *oldpath, int newdirfd, const char *newpath); int
  // linkat(int fd1, const char *path1, int fd2, const char *path2, int flag);
  // int unlinkat(int fd, const char *path, int flag);    int readlinkat(int
  // dirfd, const char *pathname, char *buf, size_t bufsiz);
  addToFunctionSummaryMap("linkat", Summary(NoEvalCall)
                                        .ArgConstraint(NotNull(ArgNo(1)))
                                        .ArgConstraint(NotNull(ArgNo(3))));

  // int unlinkat(int fd, const char *path, int flag);
  addToFunctionSummaryMap("unlinkat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int unlink(const char *pathname);    int mq_unlink(const char *name);
  addToFunctionSummaryMap("unlink",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int stat(const char *file_name, struct stat *buf);
  addToFunctionSummaryMap("stat", Summary(NoEvalCall)
                                      .ArgConstraint(NotNull(ArgNo(0)))
                                      .ArgConstraint(NotNull(ArgNo(1))));

  // int lstat(const char *file_name, struct stat *buf);
  addToFunctionSummaryMap("lstat", Summary(NoEvalCall)
                                       .ArgConstraint(NotNull(ArgNo(0)))
                                       .ArgConstraint(NotNull(ArgNo(1))));

  // int fstat(int fd, struct stat *statbuf);
  addToFunctionSummaryMap("fstat", Summary(NoEvalCall)
                                       .ArgConstraint(NotNull(ArgNo(1))));

  // int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int
  // flags);    Note: fstatat64() is a large-file version of the fstatat()
  // function as defined in POSIX 1003.1-2008 (ISO/IEC 9945-2009).
  addToFunctionSummaryMap("fstatat", Summary(NoEvalCall)
                                         .ArgConstraint(NotNull(ArgNo(1)))
                                         .ArgConstraint(NotNull(ArgNo(2))));

  // Note: fstatat64() is a large-file version of the fstatat() function as
  // defined in POSIX 1003.1-2008 (ISO/IEC 9945-2009).    int fstatat64(int
  // dirfd, const char *pathname, struct stat64  *statbuf, int flags);
  addToFunctionSummaryMap("fstatat64", Summary(NoEvalCall)
                                           .ArgConstraint(NotNull(ArgNo(1)))
                                           .ArgConstraint(NotNull(ArgNo(2))));

  // int __fxstatat64 (int __ver, int __fildes, const char *__filename,
  //			 struct stat64 *__stat_buf, int __flag)
  addToFunctionSummaryMap("__fxstatat64",
                          Summary(NoEvalCall)
                              .ArgConstraint(NotNull(ArgNo(2)))
                              .ArgConstraint(NotNull(ArgNo(3))));

  // int chmod(const char *path, mode_t mode);    int fchmod(int fildes, mode_t
  // mode);
  addToFunctionSummaryMap("chmod",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int fchmod(int fildes, mode_t mode);
  addToFunctionSummaryMap(
      "fchmod",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int chown(const char *path, uid_t owner, gid_t group);    int lchown(const
  // char *path, uid_t owner, gid_t group);    int fchown(int fildes, uid_t
  // owner, gid_t group);
  addToFunctionSummaryMap("chown",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int lchown(const char *path, uid_t owner, gid_t group);
  addToFunctionSummaryMap("lchown",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int fchown(int fildes, uid_t owner, gid_t group);
  addToFunctionSummaryMap(
      "fchown",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int utime(const char *filename, struct utimbuf *buf);
  addToFunctionSummaryMap("utime",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int futimens(int fd, const struct timespec times[2]);
  addToFunctionSummaryMap(
      "futimens",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int utimensat(int dirfd, const char *pathname, const struct timespec
  // times[2], int flags);
  addToFunctionSummaryMap("utimensat",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int utimes(const char *filename, const struct timeval times[2]);
  addToFunctionSummaryMap("utimes",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // DIR *opendir(const char *name);    DIR *fdopendir(int fd);
  addToFunctionSummaryMap("opendir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // DIR *fdopendir(int fd);
  addToFunctionSummaryMap(
      "fdopendir",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int isatty(int fildes);
  addToFunctionSummaryMap(
      "isatty",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // FILE *popen(const char *command, const char *type);
  addToFunctionSummaryMap("popen", Summary(NoEvalCall)
                                       .ArgConstraint(NotNull(ArgNo(0)))
                                       .ArgConstraint(NotNull(ArgNo(1))));

  // int pclose(FILE *stream);
  addToFunctionSummaryMap("pclose",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int setsockopt(int socket, int level, int option_name,
  addToFunctionSummaryMap(
      "setsockopt",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(3)))
          .ArgConstraint(BufferSize(3, 4))
          .ArgConstraint(ArgumentCondition(4, WithinRange, Range(0, Max))));

  // int getsockopt(int socket, int level, int option_name,
  addToFunctionSummaryMap("getsockopt", Summary(NoEvalCall)
                                            .ArgConstraint(NotNull(ArgNo(3)))
                                            .ArgConstraint(NotNull(ArgNo(4))));

  // int dlclose(void *handle);    int pclose(FILE *stream);    int close(int
  // fildes);    int mq_close(mqd_t);    void dbm_close(DBM *db);    int
  // catclose(nl_catd catd);
  addToFunctionSummaryMap("close", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // size_t confstr(int, char *, size_t);
  addToFunctionSummaryMap(
      "confstr",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // long int fpathconf(int fildes, int name);
  addToFunctionSummaryMap(
      "fpathconf",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // long int fpathconf(int fildes, int name);    long int pathconf(const char
  // *path, int name);
  addToFunctionSummaryMap("pathconf",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // FILE *fdopen(int fd, const char *mode);
  addToFunctionSummaryMap("fdopen", Summary(NoEvalCall)
                                        .ArgConstraint(ArgumentCondition(
                                            0, WithinRange, Range(0, Max)))
                                        .ArgConstraint(NotNull(ArgNo(1))));

  // void rewinddir(DIR *dir);
  addToFunctionSummaryMap("rewinddir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // void seekdir(DIR *dirp, long loc);
  addToFunctionSummaryMap("seekdir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int rand_r(unsigned int *seedp);
  addToFunctionSummaryMap("rand_r",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int strcasecmp(const char *s1, const char *s2);
  addToFunctionSummaryMap("strcasecmp", Summary(EvalCallAsPure)
                                            .ArgConstraint(NotNull(ArgNo(0)))
                                            .ArgConstraint(NotNull(ArgNo(1))));

  // int strncasecmp(const char *s1, const char *s2, size_t n);
  addToFunctionSummaryMap(
      "strncasecmp",
      Summary(EvalCallAsPure)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
  addToFunctionSummaryMap(
      "sendfile",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
          .ArgConstraint(ArgumentCondition(3, WithinRange, Range(1, Max))));

  // ssize_t read(int fd, void *buf, size_t count);
  //addToFunctionSummaryMap(
      //"read",
      //Summary(NoEvalCall)
          //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          //.ArgConstraint(BufferSize(1, 2))
          //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  //// ssize_t write(int fildes, const void *buf, size_t nbyte);
  //addToFunctionSummaryMap(
      //"write",
      //Summary(NoEvalCall)
          //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          //.ArgConstraint(BufferSize(1, 2))
          //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // ssize_t recv(int sockfd, void *buf, size_t len, int flags);
  addToFunctionSummaryMap("recv", Summary(NoEvalCall)
                                      .ArgConstraint(ArgumentCondition(
                                          0, WithinRange, Range(0, Max)))
                                      .ArgConstraint(BufferSize(1, 2)));

  // ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
  addToFunctionSummaryMap(
      "recvfrom",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          .ArgConstraint(BufferSize(1, 2)));

  // ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
  addToFunctionSummaryMap(
      "recvmsg",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // ssize_t send(int sockfd, const void *buf, size_t len, int flags);    int
  // mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned
  // msg_prio);    int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t
  // msg_len, unsigned msg_prio, const struct timespec *abstime);
  addToFunctionSummaryMap("send", Summary(NoEvalCall)
                                      .ArgConstraint(ArgumentCondition(
                                          0, WithinRange, Range(0, Max)))
                                      .ArgConstraint(BufferSize(1, 2)));

  // ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
  addToFunctionSummaryMap("sendto", Summary(NoEvalCall)
                                        .ArgConstraint(ArgumentCondition(
                                            0, WithinRange, Range(0, Max)))
                                        .ArgConstraint(BufferSize(1, 2)));

  // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
  addToFunctionSummaryMap(
      "sendmsg",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t
  // offset);
  addToFunctionSummaryMap(
      "mmap",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(1, Max)))
          .ArgConstraint(ArgumentCondition(4, WithinRange, Range(0, Max))));

  // void *mmap64(void *addr, size_t length, int prot, int flags, int fd,
  // off64_t offset);
  addToFunctionSummaryMap(
      "mmap64",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(1, Max)))
          .ArgConstraint(ArgumentCondition(4, WithinRange, Range(0, Max))));

  // int munmap(void *addr, size_t length);
  addToFunctionSummaryMap(
      "munmap",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(1, Max))));

  // int fcntl(int fd, int cmd, ... /* arg */ );
  addToFunctionSummaryMap("fcntl", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // int ioctl(int fd, unsigned long request, ...);
  addToFunctionSummaryMap("ioctl", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // int socketpair(int domain, int type, int protocol, int sv[2]);
  addToFunctionSummaryMap("socketpair",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(3))));

  // int pipe(int fildes[2]);
  addToFunctionSummaryMap("pipe",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *getwd(char *path_name);
  addToFunctionSummaryMap("getwd",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int mq_notify(mqd_t, const struct sigevent *);
  addToFunctionSummaryMap("mq_notify",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned
  // *msg_prio);
  addToFunctionSummaryMap(
      "mq_receive",
      Summary(NoEvalCall)
          .ArgConstraint(BufferSize(1, 2))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // int mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned
  // msg_prio);
  addToFunctionSummaryMap("mq_send",
                          Summary(NoEvalCall).ArgConstraint(BufferSize(1, 2)));

  // ssize_t mq_timedreceive(mqd_t mqdes, char *restrict msg_ptr, size_t
  // msg_len, unsigned *restrict msg_prio, const struct timespec *restrict
  // abstime);
  addToFunctionSummaryMap("mq_timedreceive",
                          Summary(NoEvalCall).ArgConstraint(BufferSize(1, 2)));

  // int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned
  // msg_prio, const struct timespec *abstime);
  addToFunctionSummaryMap("mq_timedsend",
                          Summary(NoEvalCall).ArgConstraint(BufferSize(1, 2)));

  // int mq_unlink(const char *name);
  addToFunctionSummaryMap("mq_unlink",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int dbm_clearerr(DBM *db);
  addToFunctionSummaryMap("dbm_clearerr",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // void dbm_close(DBM *db);
  addToFunctionSummaryMap("dbm_close",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int dbm_delete(DBM *db, datum key);
  addToFunctionSummaryMap("dbm_delete",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int dbm_error(DBM *db);
  addToFunctionSummaryMap("dbm_error",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // datum dbm_fetch(DBM *db, datum key);
  addToFunctionSummaryMap("dbm_fetch",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // datum dbm_firstkey(DBM *db);
  addToFunctionSummaryMap("dbm_firstkey",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // datum dbm_nextkey(DBM *db);
  addToFunctionSummaryMap("dbm_nextkey",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // DBM *dbm_open(const char *file, int open_flags, mode_t file_mode);
  addToFunctionSummaryMap("dbm_open",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int dbm_store(DBM *db, datum key, datum content, int store_mode);
  addToFunctionSummaryMap("dbm_store",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // void freeaddrinfo(struct addrinfo *ai);
  addToFunctionSummaryMap("freeaddrinfo",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int getnameinfo(const struct sockaddr *restrict sa,
  addToFunctionSummaryMap(
      "getnameinfo",
      Summary(NoEvalCall)
          .ArgConstraint(BufferSize(0, 1))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
          .ArgConstraint(BufferSize(2, 3))
          .ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max)))
          .ArgConstraint(BufferSize(4, 5))
          .ArgConstraint(ArgumentCondition(5, WithinRange, Range(0, Max))));

  // int uname(struct utsname *buf);
  addToFunctionSummaryMap("uname",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *strtok_r(char *str, const char *delim, char **saveptr);
  addToFunctionSummaryMap("strtok_r", Summary(EvalCallAsPure)
                                          .ArgConstraint(NotNull(ArgNo(1)))
                                          .ArgConstraint(NotNull(ArgNo(2))));

  // int getpwnam_r(const char *name, struct passwd *pwd, char *buffer, size_t
  // bufsize, struct passwd **result);
  addToFunctionSummaryMap(
      "getpwnam_r",
      Summary(NoEvalCall)
          .ArgConstraint(BufferSize(2, 3))
          .ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max))));

  // int getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t bufsize,
  // struct passwd **result);
  addToFunctionSummaryMap(
      "getpwuid_r",
      Summary(NoEvalCall)
          .ArgConstraint(BufferSize(2, 3))
          .ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max))));

  // nl_catd catopen(const char *name, int oflag);
  addToFunctionSummaryMap("catopen",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int regcomp(regex_t *restrict preg, const char *restrict pattern, int
  // cflags);
  addToFunctionSummaryMap("regcomp",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // size_t regerror(int errcode, const regex_t *restrict preg, char *restrict
  // errbuf, size_t errbuf_size);
  addToFunctionSummaryMap(
      "regerror",
      Summary(NoEvalCall)
          .ArgConstraint(BufferSize(2, 3))
          .ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max))));

  // int regexec(const regex_t *restrict preg, const char *restrict string,
  // size_t nmatch, regmatch_t pmatch[restrict], int eflags);
  addToFunctionSummaryMap(
      "regexec",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // void regfree(regex_t *preg);
  addToFunctionSummaryMap("regfree",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int sched_getparam(pid_t pid, struct sched_param *param);
  addToFunctionSummaryMap(
      "sched_getparam",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          .ArgConstraint(NotNull(ArgNo(1))));

  // int sched_getscheduler(pid_t pid);
  addToFunctionSummaryMap(
      "sched_getscheduler",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int sched_rr_get_interval(pid_t pid, struct timespec *interval);
  addToFunctionSummaryMap("sched_rr_get_interval",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int sched_setscheduler(pid_t pid, int policy, const struct sched_param
  // *param);
  addToFunctionSummaryMap(
      "sched_setscheduler",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // char *ecvt(double value, int ndigit, int *restrict decpt, int *restrict
  // sign);
  addToFunctionSummaryMap("ecvt", Summary(NoEvalCall)
                                      .ArgConstraint(NotNull(ArgNo(2)))
                                      .ArgConstraint(NotNull(ArgNo(3))));

  // char *fcvt(double value, int ndigit, int *restrict decpt, int *restrict
  // sign);
  addToFunctionSummaryMap("fcvt", Summary(NoEvalCall)
                                      .ArgConstraint(NotNull(ArgNo(2)))
                                      .ArgConstraint(NotNull(ArgNo(3))));

  // char *gcvt(double value, int ndigit, char *buf);
  addToFunctionSummaryMap("gcvt",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(2))));

  // off_t lseek(int fildes, off_t offset, int whence);
  addToFunctionSummaryMap("lseek", Summary(NoEvalCall)
                                       .ArgConstraint(ArgumentCondition(
                                           0, WithinRange, Range(0, Max))));

  // int nanosleep(const struct timespec *rqtp, struct timespec *rmtp);
  addToFunctionSummaryMap("nanosleep",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // void setkey(const char *key);
  addToFunctionSummaryMap("setkey",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *getpass(const char *prompt);
  addToFunctionSummaryMap("getpass",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int putenv(char *string);
  addToFunctionSummaryMap("putenv",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int setenv(const char *envname, const char *envval, int overwrite);    int
  // unsetenv(const char *name);
  addToFunctionSummaryMap("setenv", Summary(NoEvalCall)
                                        .ArgConstraint(NotNull(ArgNo(0)))
                                        .ArgConstraint(NotNull(ArgNo(1))));

  // int unsetenv(const char *name);
  addToFunctionSummaryMap("unsetenv",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct tm *localtime_r(const time_t *timep, struct tm *result);
  addToFunctionSummaryMap("localtime_r", Summary(NoEvalCall)
                                             .ArgConstraint(NotNull(ArgNo(0)))
                                             .ArgConstraint(NotNull(ArgNo(1))));

  // struct dirent *readdir(DIR *dirp);
  addToFunctionSummaryMap("readdir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
  addToFunctionSummaryMap("readdir_r", Summary(NoEvalCall)
                                           .ArgConstraint(NotNull(ArgNo(0)))
                                           .ArgConstraint(NotNull(ArgNo(1)))
                                           .ArgConstraint(NotNull(ArgNo(2))));

  // ssize_t readlink(const char *path, char *buf, size_t bufsiz);
  addToFunctionSummaryMap(
      "readlink",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(BufferSize(1, 2))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // int renameat(int olddirfd, const char *oldpath, int newdirfd, const char
  // *newpath);
  addToFunctionSummaryMap("renameat", Summary(NoEvalCall)
                                          .ArgConstraint(NotNull(ArgNo(1)))
                                          .ArgConstraint(NotNull(ArgNo(3))));

  // int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
  addToFunctionSummaryMap(
      "readlinkat",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(NotNull(ArgNo(2)))
          .ArgConstraint(BufferSize(2, 3))
          .ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max))));

  // char *asctime_r(const struct tm *tm, char *buf);
  addToFunctionSummaryMap("asctime_r", Summary(NoEvalCall)
                                           .ArgConstraint(NotNull(ArgNo(0)))
                                           .ArgConstraint(NotNull(ArgNo(1))));

  // char *asctime_r(const struct tm *tm, char *buf);    char *ctime_r(const
  // time_t *timep, char *buf);
  addToFunctionSummaryMap("ctime_r", Summary(NoEvalCall)
                                         .ArgConstraint(NotNull(ArgNo(0)))
                                         .ArgConstraint(NotNull(ArgNo(1))));

  // struct tm *gmtime_r(const time_t *timep, struct tm *result);
  addToFunctionSummaryMap("gmtime_r", Summary(NoEvalCall)
                                          .ArgConstraint(NotNull(ArgNo(0)))
                                          .ArgConstraint(NotNull(ArgNo(1))));

  // struct tm * gmtime(const time_t *tp);
  addToFunctionSummaryMap("gmtime",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int clock_gettime(clockid_t clock_id, struct timespec *tp);
  addToFunctionSummaryMap("clock_gettime",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // void makecontext(ucontext_t *ucp, void (*func)(), int argc, ...);
  addToFunctionSummaryMap("makecontext", Summary(NoEvalCall)
                                             .ArgConstraint(NotNull(ArgNo(0)))
                                             .ArgConstraint(NotNull(ArgNo(1))));

  // void swapcontext(ucontext_t *restrict oucp, const ucontext_t *restrict
  // ucp);
  addToFunctionSummaryMap("swapcontext", Summary(NoEvalCall)
                                             .ArgConstraint(NotNull(ArgNo(0)))
                                             .ArgConstraint(NotNull(ArgNo(1))));

  // void getcontext(ucontext_t *ucp);
  addToFunctionSummaryMap("getcontext",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // void bcopy(const void *s1, void *s2, size_t n);
  addToFunctionSummaryMap("bcopy", Summary(NoEvalCall)
                                       .ArgConstraint(NotNull(ArgNo(0)))
                                       .ArgConstraint(BufferSize(0, 2))
                                       .ArgConstraint(NotNull(ArgNo(1)))
                                       .ArgConstraint(BufferSize(1, 2))
                                       .ArgConstraint(ArgumentCondition(
                                           2, WithinRange, Range(0, Max))));

  // int bcmp(const void *s1, const void *s2, size_t n);
  addToFunctionSummaryMap("bcmp", Summary(NoEvalCall)
                                      .ArgConstraint(NotNull(ArgNo(0)))
                                      .ArgConstraint(NotNull(ArgNo(1)))
                                      .ArgConstraint(ArgumentCondition(
                                          2, WithinRange, Range(0, Max))));

  // void bzero(void *s, size_t n);
  addToFunctionSummaryMap("bzero", Summary(NoEvalCall)
                                       .ArgConstraint(NotNull(ArgNo(0)))
                                       .ArgConstraint(ArgumentCondition(
                                           1, WithinRange, Range(0, Max))));

  // int ftime(struct timeb *tp);
  addToFunctionSummaryMap("ftime",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // wchar_t *wcswcs(const wchar_t *ws1, const wchar_t *ws2);
  addToFunctionSummaryMap("wcswcs", Summary(NoEvalCall)
                                        .ArgConstraint(NotNull(ArgNo(0)))
                                        .ArgConstraint(NotNull(ArgNo(1))));

  // char *stpcpy(char *desstr, const char *srcstr);
  addToFunctionSummaryMap("stpcpy", Summary(NoEvalCall)
                                        .ArgConstraint(NotNull(ArgNo(0)))
                                        .ArgConstraint(NotNull(ArgNo(1))));

  // char *index(const char *s, int c);    char *rindex(const char *s, int c);
  addToFunctionSummaryMap("index",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *rindex(const char *s, int c);
  addToFunctionSummaryMap("rindex",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_cond_signal(pthread_cond_t *cond);
  addToFunctionSummaryMap("pthread_cond_signal",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_cond_broadcast(pthread_cond_t *cond);
  addToFunctionSummaryMap("pthread_cond_broadcast",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_create(pthread_t * thread, const pthread_attr_t * attr, void
  // *(*start_routine)(void*), void * arg);
  addToFunctionSummaryMap("pthread_create",
                          Summary(NoEvalCall)
                              .ArgConstraint(NotNull(ArgNo(0)))
                              .ArgConstraint(NotNull(ArgNo(2))));

  // int pthread_attr_destroy(pthread_attr_t *attr);
  addToFunctionSummaryMap("pthread_attr_destroy",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_attr_init(pthread_attr_t *attr);
  addToFunctionSummaryMap("pthread_attr_init",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_attr_setstackaddr(pthread_attr_t *attr, void *stackaddr);
  addToFunctionSummaryMap("pthread_attr_setstackaddr",
                          Summary(NoEvalCall)
                              .ArgConstraint(NotNull(ArgNo(0)))
                              .ArgConstraint(NotNull(ArgNo(1))));

  // int pthread_attr_getstackaddr(const pthread_attr_t *attr, void
  // **stackaddr);
  addToFunctionSummaryMap("pthread_attr_getstackaddr",
                          Summary(NoEvalCall)
                              .ArgConstraint(NotNull(ArgNo(0)))
                              .ArgConstraint(NotNull(ArgNo(1))));

  // int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize);
  addToFunctionSummaryMap(
      "pthread_attr_setstacksize",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max))));

  // int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize);
  addToFunctionSummaryMap(
      "pthread_attr_setguardsize",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max))));

  // int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t
  // *stacksize);
  addToFunctionSummaryMap("pthread_attr_getstacksize",
                          Summary(NoEvalCall)
                              .ArgConstraint(NotNull(ArgNo(0)))
                              .ArgConstraint(NotNull(ArgNo(1))));

  // int pthread_attr_getguardsize(const pthread_attr_t *attr, size_t
  // *guardsize);
  addToFunctionSummaryMap("pthread_attr_getguardsize",
                          Summary(NoEvalCall)
                              .ArgConstraint(NotNull(ArgNo(0)))
                              .ArgConstraint(NotNull(ArgNo(1))));

  // int pthread_mutex_init(pthread_mutex_t *restrict mutex, const
  // pthread_mutexattr_t *restrict attr);
  addToFunctionSummaryMap("pthread_mutex_init",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_mutex_destroy(pthread_mutex_t *mutex);
  addToFunctionSummaryMap("pthread_mutex_destroy",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_mutex_lock(pthread_mutex_t *mutex);
  addToFunctionSummaryMap("pthread_mutex_lock",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_mutex_trylock(pthread_mutex_t *mutex);
  addToFunctionSummaryMap("pthread_mutex_trylock",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int pthread_mutex_unlock(pthread_mutex_t *mutex);
  addToFunctionSummaryMap("pthread_mutex_unlock",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *crypt(const char *key, const char *salt);
  addToFunctionSummaryMap("crypt", Summary(NoEvalCall)
                                       .ArgConstraint(NotNull(ArgNo(0)))
                                       .ArgConstraint(NotNull(ArgNo(1))));

  // char *ttyname(int fd);
  addToFunctionSummaryMap(
      "ttyname",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // char *ttyname(int fd);
  addToFunctionSummaryMap(
      "ttyname_r",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(BufferSize(1, 2))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // struct spwd *getspnam(const char *name);
  addToFunctionSummaryMap("getspnam",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct spwd *fgetspent(FILE *fp);
  addToFunctionSummaryMap("fgetspent",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct spwd *sgetspent(const char *s);
  addToFunctionSummaryMap("sgetspent",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // struct passwd *fgetpwent(FILE *stream);
  addToFunctionSummaryMap("fgetpwent",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int getgrent_r(struct group *gbuf, char *buf, size_t buflen, struct group
  // **gbufp)
  addToFunctionSummaryMap(
      "getgrent_r",
      Summary(NoEvalCall)
          .ArgConstraint(BufferSize(1, 2))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // struct group *fgetgrent(FILE *stream);
  addToFunctionSummaryMap("fgetgrent",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int getnetgrent(char **host, char **user, char **domain);
  addToFunctionSummaryMap("getnetgrent", Summary(NoEvalCall)
                                             .ArgConstraint(NotNull(ArgNo(0)))
                                             .ArgConstraint(NotNull(ArgNo(1)))
                                             .ArgConstraint(NotNull(ArgNo(2))));

  // struct group *getgrnam(const char *name);
  addToFunctionSummaryMap("getgrnam",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // char *realpath(const char *path, char *resolved_path);
  addToFunctionSummaryMap("realpath",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // long telldir(DIR *dirp);
  addToFunctionSummaryMap("telldir",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int scandir(const char *dirp,
  addToFunctionSummaryMap("scandir", Summary(NoEvalCall)
                                         .ArgConstraint(NotNull(ArgNo(0)))
                                         .ArgConstraint(NotNull(ArgNo(1)))
                                         .ArgConstraint(NotNull(ArgNo(3))));

  // int fileno(FILE *stream);
  addToFunctionSummaryMap("fileno",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int fseeko(FILE *stream, off_t offset, int whence);
  addToFunctionSummaryMap("fseeko",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // off_t ftello(FILE *stream);
  addToFunctionSummaryMap("ftello",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int execv(const char *path, char *const argv[]);
  addToFunctionSummaryMap("execv",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int execvp(const char *file, char *const argv[]);
  addToFunctionSummaryMap("execvp",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // size_t strnlen(const char *s, size_t maxlen);
  addToFunctionSummaryMap(
      "strnlen",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max))));

  // size_t wcsnlen(const wchar_t *s, size_t maxlen);
  addToFunctionSummaryMap(
      "wcsnlen",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max))));

  // int shmget(key_t key, size_t size, int shmflg);
  addToFunctionSummaryMap(
      "shmget",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max))));

  // int getrlimit(int resource, struct rlimit *rlim);
  addToFunctionSummaryMap("getrlimit",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int setrlimit(int resource, const struct rlimit *rlim);
  addToFunctionSummaryMap("setrlimit",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int glob(const char *pattern, int flags, int (*errfunc) (const char *epath,
  // int eerrno), glob_t *pglob);
  addToFunctionSummaryMap("glob", Summary(NoEvalCall)
                                      .ArgConstraint(NotNull(ArgNo(0)))
                                      .ArgConstraint(NotNull(ArgNo(3))));

  // void globfree(glob_t *pglob)
  addToFunctionSummaryMap("globfree",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // wchar_t *wcpncpy(wchar_t *dest, const wchar_t *src, size_t n);
  addToFunctionSummaryMap(
      "wcpncpy",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(BufferSize(0, 2))
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // char *stpncpy(char *dest, const char *src, size_t n);
  addToFunctionSummaryMap(
      "stpncpy",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(BufferSize(0, 2))
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // void *memccpy(void *dest, const void *src, int c, size_t n);
  addToFunctionSummaryMap(
      "memccpy",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
          .ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max))));

  // int getopt(int argc, char * const argv[], const char *optstring);
  addToFunctionSummaryMap("getopt", Summary(NoEvalCall)
                                        .ArgConstraint(ArgumentCondition(
                                            0, WithinRange, Range(0, Max)))
                                        .ArgConstraint(NotNull(ArgNo(1)))
                                        .ArgConstraint(NotNull(ArgNo(2))));

  // int getitimer(int which, struct itimerval *curr_value);
  addToFunctionSummaryMap("getitimer",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int sigsuspend(const sigset_t *mask);
  addToFunctionSummaryMap("sigsuspend",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int getrusage(int who, struct rusage *usage);
  addToFunctionSummaryMap("getrusage",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(1))));

  // int sigemptyset(sigset_t *set);
  addToFunctionSummaryMap("sigemptyset",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int sigfillset(sigset_t *set);
  addToFunctionSummaryMap("sigfillset",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int sigaddset(sigset_t *set, int signum);
  addToFunctionSummaryMap("sigaddset",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int sigdelset(sigset_t *set, int signum);
  addToFunctionSummaryMap("sigdelset",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int sigismember(const sigset_t *set, int signum);
  addToFunctionSummaryMap("sigismember",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
  addToFunctionSummaryMap(
      "msgrcv",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(BufferSize(1, 2))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
  addToFunctionSummaryMap(
      "msgsnd",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(1)))
          .ArgConstraint(BufferSize(1, 2))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // int tcflow(int fildes, int action);
  addToFunctionSummaryMap(
      "tcflow",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int tcflush(int fildes, int queue_selector);
  addToFunctionSummaryMap(
      "tcflush",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int tcsendbreak(int fildes, int duration);
  addToFunctionSummaryMap(
      "tcsendbreak",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // int tcgetattr(int fildes, struct termios *termios_p);
  addToFunctionSummaryMap(
      "tcgetattr",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          .ArgConstraint(NotNull(ArgNo(1))));

  // int tcsetattr(int fildes, int optional_actions, const struct termios
  // *termios_p);
  addToFunctionSummaryMap(
      "tcsetattr",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
          .ArgConstraint(NotNull(ArgNo(2))));

  // int cfsetospeed(struct termios *termios_p, speed_t speed);
  addToFunctionSummaryMap("cfsetospeed",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int cfsetispeed(struct termios *termios_p, speed_t speed);
  addToFunctionSummaryMap("cfsetispeed",
                          Summary(NoEvalCall).ArgConstraint(NotNull(ArgNo(0))));

  // int tcdrain(int fildes);
  addToFunctionSummaryMap(
      "tcdrain",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // void swab(const void * src, void* dest, ssize_t bytes);
  addToFunctionSummaryMap("swab", Summary(NoEvalCall)
                                      .ArgConstraint(BufferSize(0, 2))
                                      .ArgConstraint(NotNull(ArgNo(1)))
                                      .ArgConstraint(BufferSize(1, 2))
                                      .ArgConstraint(ArgumentCondition(
                                          2, WithinRange, Range(0, Max))));

  // int gethostname(char *name, size_t len);
  addToFunctionSummaryMap(
      "gethostname",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(BufferSize(0, 1))
          .ArgConstraint(ArgumentCondition(1, WithinRange, Range(1, Max))));

  // int posix_memalign(void **memptr, size_t alignment, size_t size);
  addToFunctionSummaryMap(
      "posix_memalign",
      Summary(NoEvalCall)
          .ArgConstraint(NotNull(ArgNo(0)))
          .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max))));

  // void *valloc(size_t size);
  addToFunctionSummaryMap(
      "valloc",
      Summary(NoEvalCall)
          .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max))));

  // END POSIX

  // Functions for testing.
  if (ChecksEnabled[CK_StdCLibraryFunctionsTesterChecker]) {
    addToFunctionSummaryMap("__buf_size_arg_constraint",
                            Summary(ArgTypes{ConstVoidPtrTy, SizeTy},
                                    RetType{IntTy}, EvalCallAsPure)
                                .ArgConstraint(BufferSize(0, 1)));
    addToFunctionSummaryMap("__buf_size_arg_constraint_mul",
                            Summary(ArgTypes{ConstVoidPtrTy, SizeTy, SizeTy},
                                    RetType{IntTy}, EvalCallAsPure)
                                .ArgConstraint(BufferSize(0, 1, 2)));
    addToFunctionSummaryMap(
        "__two_constrained_args",
        Summary(ArgTypes{IntTy, IntTy}, RetType{IntTy}, EvalCallAsPure)
            .ArgConstraint(ArgumentCondition(0U, WithinRange, SingleValue(1)))
            .ArgConstraint(ArgumentCondition(1U, WithinRange, SingleValue(1))));
    addToFunctionSummaryMap(
        "__arg_constrained_twice",
        Summary(ArgTypes{IntTy}, RetType{IntTy}, EvalCallAsPure)
            .ArgConstraint(ArgumentCondition(0U, OutOfRange, SingleValue(1)))
            .ArgConstraint(ArgumentCondition(0U, OutOfRange, SingleValue(2))));
    addToFunctionSummaryMap(
        "__defaultparam",
        Summary(ArgTypes{Irrelevant, IntTy}, RetType{IntTy}, EvalCallAsPure)
            .ArgConstraint(NotNull(ArgNo(0))));
    addToFunctionSummaryMap("__variadic",
                            Summary(ArgTypes{VoidPtrTy, ConstCharPtrTy},
                                    RetType{IntTy}, EvalCallAsPure)
                                .ArgConstraint(NotNull(ArgNo(0)))
                                .ArgConstraint(NotNull(ArgNo(1))));
    addToFunctionSummaryMap(
        "__lazy_range",
        Summary(ArgTypes{IntTy, IntTy}, RetType{IntTy}, EvalCallAsPure)
            .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, 100)))
            .ArgConstraint(
                ArgumentCondition(1, WithinRange, Range(0, Max))));
  }
}

void ento::registerStdCLibraryFunctionsChecker(CheckerManager &mgr) {
  auto *Checker = mgr.registerChecker<StdLibraryFunctionsChecker>();
  Checker->DisplayLoadedSummaries =
      mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "DisplayLoadedSummaries");
}

bool ento::shouldRegisterStdCLibraryFunctionsChecker(const CheckerManager &mgr) {
  return true;
}

#define REGISTER_CHECKER(name)                                                 \
  void ento::register##name(CheckerManager &mgr) {                             \
    StdLibraryFunctionsChecker *checker =                                      \
        mgr.getChecker<StdLibraryFunctionsChecker>();                          \
    checker->ChecksEnabled[StdLibraryFunctionsChecker::CK_##name] = true;      \
    checker->CheckNames[StdLibraryFunctionsChecker::CK_##name] =               \
        mgr.getCurrentCheckerName();                                           \
  }                                                                            \
                                                                               \
  bool ento::shouldRegister##name(const CheckerManager &mgr) { return true; }

REGISTER_CHECKER(StdCLibraryFunctionArgsChecker)
REGISTER_CHECKER(StdCLibraryFunctionsTesterChecker)
