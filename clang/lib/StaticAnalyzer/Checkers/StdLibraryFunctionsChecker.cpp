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

using namespace clang;
using namespace clang::ento;

namespace {
class StdLibraryFunctionsChecker
    : public Checker<check::PreCall, check::PostCall, eval::Call> {

  class Summary;

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

    // Check whether the constraint is malformed or not. It is malformed if the
    // specified argument has a mismatch with the given FunctionDecl (e.g. the
    // arg number is out-of-range of the function's argument list).
    bool checkValidity(const FunctionDecl *FD) const {
      const bool ValidArg = ArgN == Ret || ArgN < FD->getNumParams();
      assert(ValidArg && "Arg out of range!");
      if (!ValidArg)
        return false;
      // Subclasses may further refine the validation.
      return checkSpecificValidity(FD);
    }
    ArgNo getArgNo() const { return ArgN; }

  protected:
    ArgNo ArgN; // Argument to which we apply the constraint.

    /// Do polymorphic sanity check on the constraint.
    virtual bool checkSpecificValidity(const FunctionDecl *FD) const {
      return true;
    }
  };

  /// Given a range, should the argument stay inside or outside this range?
  enum RangeKind { OutOfRange, WithinRange };

  /// Encapsulates a single range on a single symbol within a branch.
  class RangeConstraint : public ValueConstraint {
    RangeKind Kind;      // Kind of range definition.
    IntRangeVector Args; // Polymorphic arguments.

  public:
    RangeConstraint(ArgNo ArgN, RangeKind Kind, const IntRangeVector &Args)
        : ValueConstraint(ArgN), Kind(Kind), Args(Args) {}

    const IntRangeVector &getRanges() const {
      return Args;
    }

  private:
    ProgramStateRef applyAsOutOfRange(ProgramStateRef State,
                                      const CallEvent &Call,
                                      const Summary &Summary) const;
    ProgramStateRef applyAsWithinRange(ProgramStateRef State,
                                       const CallEvent &Call,
                                       const Summary &Summary) const;
  public:
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

    bool checkSpecificValidity(const FunctionDecl *FD) const override {
      const bool ValidArg =
          getArgType(FD, ArgN)->isIntegralType(FD->getASTContext());
      assert(ValidArg &&
             "This constraint should be applied on an integral type");
      return ValidArg;
    }
  };

  class ComparisonConstraint : public ValueConstraint {
    BinaryOperator::Opcode Opcode;
    ArgNo OtherArgN;

  public:
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

    bool checkSpecificValidity(const FunctionDecl *FD) const override {
      const bool ValidArg = getArgType(FD, ArgN)->isPointerType();
      assert(ValidArg &&
             "This constraint should be applied only on a pointer type");
      return ValidArg;
    }
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
    BufferSizeConstraint(ArgNo Buffer, ArgNo BufSize)
        : ValueConstraint(Buffer), SizeArgN(BufSize) {}

    BufferSizeConstraint(ArgNo Buffer, ArgNo BufSize, ArgNo BufSizeMultiplier)
        : ValueConstraint(Buffer), SizeArgN(BufSize),
          SizeMultiplierArgN(BufSizeMultiplier) {}

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
                                      Summary.getArgType(SizeArgN));
      }
      // The dynamic size of the buffer argument, got from the analyzer engine.
      SVal BufDynSize = getDynamicSizeWithOffset(State, BufV);

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
      llvm_unreachable("Size argument or the dynamic size is Undefined");
    }

    ValueConstraintPtr negate() const override {
      BufferSizeConstraint Tmp(*this);
      Tmp.Op = BinaryOperator::negateComparisonOp(Op);
      return std::make_shared<BufferSizeConstraint>(Tmp);
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
    Signature(ArgTypes ArgTys, QualType RetTy) : ArgTys(ArgTys), RetTy(RetTy) {
      assertRetTypeSuitableForSignature(RetTy);
      for (size_t I = 0, E = ArgTys.size(); I != E; ++I) {
        QualType ArgTy = ArgTys[I];
        assertArgTypeSuitableForSignature(ArgTy);
      }
    }
    bool matches(const FunctionDecl *FD) const;

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

  static QualType getArgType(const FunctionDecl *FD, ArgNo ArgN) {
    assert(FD && "Function must be set");
    QualType T = (ArgN == Ret)
                     ? FD->getReturnType().getCanonicalType()
                     : FD->getParamDecl(ArgN)->getType().getCanonicalType();
    return T;
  }

  using Cases = std::vector<ConstraintSet>;

  /// A summary includes information about
  ///   * function prototype (signature)
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
  ///
  /// Application of a summary:
  ///   The signature and argument constraints together contain information
  ///   about which functions are handled by the summary. The signature can use
  ///   "wildcards", i.e. Irrelevant types. Irrelevant type of a parameter in
  ///   a signature means that type is not compared to the type of the parameter
  ///   in the found FunctionDecl. Argument constraints may specify additional
  ///   rules for the given parameter's type, those rules are checked once the
  ///   signature is matched.
  class Summary {
    const Signature Sign;
    const InvalidationKind InvalidationKd;
    Cases CaseConstraints;
    ConstraintSet ArgConstraints;

    // The function to which the summary applies. This is set after lookup and
    // match to the signature.
    const FunctionDecl *FD = nullptr;

  public:
    Summary(ArgTypes ArgTys, QualType RetTy, InvalidationKind InvalidationKd)
        : Sign(ArgTys, RetTy), InvalidationKd(InvalidationKd) {}

    Summary &Case(ConstraintSet&& CS) {
      CaseConstraints.push_back(std::move(CS));
      return *this;
    }
    Summary &ArgConstraint(ValueConstraintPtr VC) {
      ArgConstraints.push_back(VC);
      return *this;
    }

    InvalidationKind getInvalidationKd() const { return InvalidationKd; }
    const Cases &getCaseConstraints() const { return CaseConstraints; }
    const ConstraintSet &getArgConstraints() const { return ArgConstraints; }

    QualType getArgType(ArgNo ArgN) const {
      return StdLibraryFunctionsChecker::getArgType(FD, ArgN);
    }

    // Returns true if the summary should be applied to the given function.
    // And if yes then store the function declaration.
    bool matchesAndSet(const FunctionDecl *FD) {
      bool Result = Sign.matches(FD) && validateByConstraints(FD);
      if (Result) {
        assert(!this->FD && "FD must not be set more than once");
        this->FD = FD;
      }
      return Result;
    }

  private:
    // Once we know the exact type of the function then do sanity check on all
    // the given constraints.
    bool validateByConstraints(const FunctionDecl *FD) const {
      for (const ConstraintSet &Case : CaseConstraints)
        for (const ValueConstraintPtr &Constraint : Case)
          if (!Constraint->checkValidity(FD))
            return false;
      for (const ValueConstraintPtr &Constraint : ArgConstraints)
        if (!Constraint->checkValidity(FD))
          return false;
      return true;
    }
  };

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
  bool ModelPOSIX = false;

private:
  Optional<Summary> findFunctionSummary(const FunctionDecl *FD,
                                        CheckerContext &C) const;
  Optional<Summary> findFunctionSummary(const CallEvent &Call,
                                        CheckerContext &C) const;

  void initFunctionSummaries(CheckerContext &C) const;

  void reportBug(const CallEvent &Call, ExplodedNode *N,
                 CheckerContext &C) const {
    if (!ChecksEnabled[CK_StdCLibraryFunctionArgsChecker])
      return;
    // TODO Add detailed diagnostic.
    StringRef Msg = "Function argument constraint is not satisfied";
    if (!BT_InvalidArg)
      BT_InvalidArg = std::make_unique<BugType>(
          CheckNames[CK_StdCLibraryFunctionArgsChecker],
          "Unsatisfied argument constraints", categories::LogicError);
    auto R = std::make_unique<PathSensitiveBugReport>(*BT_InvalidArg, Msg, N);
    bugreporter::trackExpressionValue(N, Call.getArgExpr(0), *R);
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
  QualType T = Summary.getArgType(getArgNo());
  SVal V = getArgSVal(Call, getArgNo());

  if (auto N = V.getAs<NonLoc>()) {
    const IntRangeVector &R = getRanges();
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
  QualType T = Summary.getArgType(getArgNo());
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
    const IntRangeVector &R = getRanges();
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
  QualType T = Summary.getArgType(getArgNo());
  SVal V = getArgSVal(Call, getArgNo());

  BinaryOperator::Opcode Op = getOpcode();
  ArgNo OtherArg = getOtherArgNo();
  SVal OtherV = getArgSVal(Call, OtherArg);
  QualType OtherT = Summary.getArgType(OtherArg);
  // Note: we avoid integral promotion for comparison.
  OtherV = SVB.evalCast(OtherV, T, OtherT);
  if (auto CompV = SVB.evalBinOp(State, Op, V, OtherV, CondT)
                       .getAs<DefinedOrUnknownSVal>())
    State = State->assume(*CompV, true);
  return State;
}

void StdLibraryFunctionsChecker::checkPreCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  Optional<Summary> FoundSummary = findFunctionSummary(Call, C);
  if (!FoundSummary)
    return;

  const Summary &Summary = *FoundSummary;
  ProgramStateRef State = C.getState();

  ProgramStateRef NewState = State;
  for (const ValueConstraintPtr &Constraint : Summary.getArgConstraints()) {
    ProgramStateRef SuccessSt = Constraint->apply(NewState, Call, Summary, C);
    ProgramStateRef FailureSt =
        Constraint->negate()->apply(NewState, Call, Summary, C);
    // The argument constraint is not satisfied.
    if (FailureSt && !SuccessSt) {
      if (ExplodedNode *N = C.generateErrorNode(NewState))
        reportBug(Call, N, C);
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
  if (NewState && NewState != State)
    C.addTransition(NewState);
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
  for (const ConstraintSet &Case : Summary.getCaseConstraints()) {
    ProgramStateRef NewState = State;
    for (const ValueConstraintPtr &Constraint : Case) {
      NewState = Constraint->apply(NewState, Call, Summary, C);
      if (!NewState)
        break;
    }

    if (NewState && NewState != State)
      C.addTransition(NewState);
  }
}

bool StdLibraryFunctionsChecker::evalCall(const CallEvent &Call,
                                          CheckerContext &C) const {
  Optional<Summary> FoundSummary = findFunctionSummary(Call, C);
  if (!FoundSummary)
    return false;

  const Summary &Summary = *FoundSummary;
  switch (Summary.getInvalidationKd()) {
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

llvm::Optional<QualType> lookupType(StringRef Name, const ASTContext &ACtx) {
  IdentifierInfo &II = ACtx.Idents.get(Name);
  auto LookupRes = ACtx.getTranslationUnitDecl()->lookup(&II);
  if (LookupRes.size() == 0)
    return None;

  // Prioritze typedef declarations.
  // This is needed in case of C struct typedefs. E.g.:
  //   typedef struct FILE FILE;
  // In this case, we have a RecordDecl 'struct FILE' with the name 'FILE' and
  // we have a TypedefDecl with the name 'FILE'.
  for (Decl *D : LookupRes)
    if (auto *TD = dyn_cast<TypedefNameDecl>(D))
      return ACtx.getTypeDeclType(TD).getCanonicalType();

  // Find the first TypeDecl.
  // There maybe cases when a function has the same name as a struct.
  // E.g. in POSIX: `struct stat` and the function `stat()`:
  //   int stat(const char *restrict path, struct stat *restrict buf);
  for (Decl *D : LookupRes)
    if (auto *TD = dyn_cast<TypeDecl>(D))
      return ACtx.getTypeDeclType(TD).getCanonicalType();
  return None;
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
  const QualType VoidTy = ACtx.VoidTy;
  const QualType IntTy = ACtx.IntTy;
  const QualType UnsignedIntTy = ACtx.UnsignedIntTy;
  const QualType LongTy = ACtx.LongTy;
  const QualType LongLongTy = ACtx.LongLongTy;
  const QualType SizeTy = ACtx.getSizeType();

  const QualType VoidPtrTy = ACtx.VoidPtrTy; // void *
  const QualType IntPtrTy = ACtx.getPointerType(IntTy); // int *
  const QualType UnsignedIntPtrTy =
      ACtx.getPointerType(UnsignedIntTy); // unsigned int *
  const QualType VoidPtrRestrictTy =
      ACtx.getLangOpts().C99 ? ACtx.getRestrictType(VoidPtrTy) // void *restrict
                             : VoidPtrTy;
  const QualType ConstVoidPtrTy =
      ACtx.getPointerType(ACtx.VoidTy.withConst()); // const void *
  const QualType CharPtrTy = ACtx.getPointerType(ACtx.CharTy); // char *
  const QualType CharPtrRestrictTy =
      ACtx.getLangOpts().C99 ? ACtx.getRestrictType(CharPtrTy) // char *restrict
                             : CharPtrTy;
  const QualType ConstCharPtrTy =
      ACtx.getPointerType(ACtx.CharTy.withConst()); // const char *
  const QualType ConstCharPtrRestrictTy =
      ACtx.getLangOpts().C99
          ? ACtx.getRestrictType(ConstCharPtrTy) // const char *restrict
          : ConstCharPtrTy;
  const QualType Wchar_tPtrTy = ACtx.getPointerType(ACtx.WCharTy); // wchar_t *
  const QualType ConstWchar_tPtrTy =
      ACtx.getPointerType(ACtx.WCharTy.withConst()); // const wchar_t *
  const QualType ConstVoidPtrRestrictTy =
      ACtx.getLangOpts().C99
          ? ACtx.getRestrictType(ConstVoidPtrTy) // const void *restrict
          : ConstVoidPtrTy;

  const RangeInt IntMax = BVF.getMaxValue(IntTy).getLimitedValue();
  const RangeInt UnsignedIntMax =
      BVF.getMaxValue(UnsignedIntTy).getLimitedValue();
  const RangeInt LongMax = BVF.getMaxValue(LongTy).getLimitedValue();
  const RangeInt LongLongMax = BVF.getMaxValue(LongLongTy).getLimitedValue();
  const RangeInt SizeMax = BVF.getMaxValue(SizeTy).getLimitedValue();

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
      for (Decl *D : LookupRes) {
        if (auto *FD = dyn_cast<FunctionDecl>(D)) {
          if (S.matchesAndSet(FD)) {
            auto Res = Map.insert({FD->getCanonicalDecl(), S});
            assert(Res.second && "Function already has a summary set!");
            (void)Res;
            if (DisplayLoadedSummaries) {
              llvm::errs() << "Loaded summary for: ";
              FD->print(llvm::errs());
              llvm::errs() << "\n";
            }
            return;
          }
        }
      }
    }
    // Add several summaries for the given name.
    void operator()(StringRef Name, const std::vector<Summary> &Summaries) {
      for (const Summary &S : Summaries)
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
                              IntRangeVector Ranges) {
    return std::make_shared<RangeConstraint>(ArgN, Kind, Ranges);
  };
  auto BufferSize = [](auto... Args) {
    return std::make_shared<BufferSizeConstraint>(Args...);
  };
  struct {
    auto operator()(RangeKind Kind, IntRangeVector Ranges) {
      return std::make_shared<RangeConstraint>(Ret, Kind, Ranges);
    }
    auto operator()(BinaryOperator::Opcode Op, ArgNo OtherArgN) {
      return std::make_shared<ComparisonConstraint>(Ret, Op, OtherArgN);
    }
  } ReturnValueCondition;
  auto Range = [](RangeInt b, RangeInt e) {
    return IntRangeVector{std::pair<RangeInt, RangeInt>{b, e}};
  };
  auto SingleValue = [](RangeInt v) {
    return IntRangeVector{std::pair<RangeInt, RangeInt>{v, v}};
  };
  auto LessThanOrEq = BO_LE;
  auto NotNull = [&](ArgNo ArgN) {
    return std::make_shared<NotNullConstraint>(ArgN);
  };

  Optional<QualType> FileTy = lookupType("FILE", ACtx);
  Optional<QualType> FilePtrTy, FilePtrRestrictTy;
  if (FileTy) {
    // FILE *
    FilePtrTy = ACtx.getPointerType(*FileTy);
    // FILE *restrict
    FilePtrRestrictTy =
        ACtx.getLangOpts().C99 ? ACtx.getRestrictType(*FilePtrTy) : *FilePtrTy;
  }

  using RetType = QualType;
  // Templates for summaries that are reused by many functions.
  auto Getc = [&]() {
    return Summary(ArgTypes{*FilePtrTy}, RetType{IntTy}, NoEvalCall)
        .Case({ReturnValueCondition(WithinRange,
                                    {{EOFv, EOFv}, {0, UCharRangeMax}})});
  };
  auto Read = [&](RetType R, RangeInt Max) {
    return Summary(ArgTypes{Irrelevant, Irrelevant, SizeTy}, RetType{R},
                   NoEvalCall)
        .Case({ReturnValueCondition(LessThanOrEq, ArgNo(2)),
               ReturnValueCondition(WithinRange, Range(-1, Max))});
  };
  auto Fread = [&]() {
    return Summary(
               ArgTypes{VoidPtrRestrictTy, SizeTy, SizeTy, *FilePtrRestrictTy},
               RetType{SizeTy}, NoEvalCall)
        .Case({
            ReturnValueCondition(LessThanOrEq, ArgNo(2)),
        })
        .ArgConstraint(NotNull(ArgNo(0)));
  };
  auto Fwrite = [&]() {
    return Summary(ArgTypes{ConstVoidPtrRestrictTy, SizeTy, SizeTy,
                            *FilePtrRestrictTy},
                   RetType{SizeTy}, NoEvalCall)
        .Case({
            ReturnValueCondition(LessThanOrEq, ArgNo(2)),
        })
        .ArgConstraint(NotNull(ArgNo(0)));
  };
  auto Getline = [&](RetType R, RangeInt Max) {
    return Summary(ArgTypes{Irrelevant, Irrelevant, Irrelevant}, RetType{R},
                   NoEvalCall)
        .Case({ReturnValueCondition(WithinRange, {{-1, -1}, {1, Max}})});
  };

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
  if (FilePtrTy) {
    addToFunctionSummaryMap("getc", Getc());
    addToFunctionSummaryMap("fgetc", Getc());
  }
  addToFunctionSummaryMap(
      "getchar", Summary(ArgTypes{}, RetType{IntTy}, NoEvalCall)
                     .Case({ReturnValueCondition(
                         WithinRange, {{EOFv, EOFv}, {0, UCharRangeMax}})}));

  // read()-like functions that never return more than buffer size.
  if (FilePtrRestrictTy) {
    addToFunctionSummaryMap("fread", Fread());
    addToFunctionSummaryMap("fwrite", Fwrite());
  }

  // We are not sure how ssize_t is defined on every platform, so we
  // provide three variants that should cover common cases.
  // FIXME these are actually defined by POSIX and not by the C standard, we
  // should handle them together with the rest of the POSIX functions.
  addToFunctionSummaryMap("read", {Read(IntTy, IntMax), Read(LongTy, LongMax),
                                   Read(LongLongTy, LongLongMax)});
  addToFunctionSummaryMap("write", {Read(IntTy, IntMax), Read(LongTy, LongMax),
                                    Read(LongLongTy, LongLongMax)});

  // getline()-like functions either fail or read at least the delimiter.
  // FIXME these are actually defined by POSIX and not by the C standard, we
  // should handle them together with the rest of the POSIX functions.
  addToFunctionSummaryMap("getline",
                          {Getline(IntTy, IntMax), Getline(LongTy, LongMax),
                           Getline(LongLongTy, LongLongMax)});
  addToFunctionSummaryMap("getdelim",
                          {Getline(IntTy, IntMax), Getline(LongTy, LongMax),
                           Getline(LongLongTy, LongLongMax)});

  if (ModelPOSIX) {

    // long a64l(const char *str64);
    addToFunctionSummaryMap(
        "a64l", Summary(ArgTypes{ConstCharPtrTy}, RetType{LongTy}, NoEvalCall)
                    .ArgConstraint(NotNull(ArgNo(0))));

    // char *l64a(long value);
    addToFunctionSummaryMap(
        "l64a", Summary(ArgTypes{LongTy}, RetType{CharPtrTy}, NoEvalCall)
                    .ArgConstraint(
                        ArgumentCondition(0, WithinRange, Range(0, LongMax))));

    // int access(const char *pathname, int amode);
    addToFunctionSummaryMap("access", Summary(ArgTypes{ConstCharPtrTy, IntTy},
                                              RetType{IntTy}, NoEvalCall)
                                          .ArgConstraint(NotNull(ArgNo(0))));

    // int faccessat(int dirfd, const char *pathname, int mode, int flags);
    addToFunctionSummaryMap(
        "faccessat", Summary(ArgTypes{IntTy, ConstCharPtrTy, IntTy, IntTy},
                             RetType{IntTy}, NoEvalCall)
                         .ArgConstraint(NotNull(ArgNo(1))));

    //// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    // addToFunctionSummaryMap("accept",
    // Summary(ArgTypes{IntTy,StructSockaddrPtrTy,Socklen_tPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(ArgumentCondition(0,
    //WithinRange, Range(0, Max)))
    //);

    //// int bind(int socket, const struct sockaddr *address, socklen_t
    ///address_len);
    // addToFunctionSummaryMap("bind",
    // Summary(ArgTypes{IntTy,ConstStructSockaddrPtrTy,Socklen_tTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(ArgumentCondition(0,
    //WithinRange, Range(0, Max))) .ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// int listen(int sockfd, int backlog);
    // addToFunctionSummaryMap("listen",
    // Summary(ArgTypes{IntTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    // addToFunctionSummaryMap("getpeername",
    // Summary(ArgTypes{IntTy,StructSockaddrPtrTy,Socklen_tPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(ArgumentCondition(0,
    //WithinRange, Range(0, Max))) .ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(NotNull(ArgNo(2)))
    //);

    //// int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    // addToFunctionSummaryMap("getsockname",
    // Summary(ArgTypes{IntTy,StructSockaddrPtrTy,Socklen_tPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(ArgumentCondition(0,
    //WithinRange, Range(0, Max))) .ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(NotNull(ArgNo(2)))
    //);

    //// int connect(int socket, const struct sockaddr *address, socklen_t
    ///address_len);
    // addToFunctionSummaryMap("connect",
    // Summary(ArgTypes{IntTy,ConstStructSockaddrPtrTy,Socklen_tTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(ArgumentCondition(0,
    //WithinRange, Range(0, Max))) .ArgConstraint(NotNull(ArgNo(1)))
    //);

    // ssize_t recvfrom(int socket, void *restrict buffer, size_t length,
    //        int flags, struct sockaddr *restrict address,
    //               socklen_t *restrict address_len);
    // addToFunctionSummaryMap("recvfrom",
    // Summary(ArgTypes{}, RetType{}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //);

    // int dup(int fildes);
    addToFunctionSummaryMap(
        "dup", Summary(ArgTypes{IntTy}, RetType{IntTy}, NoEvalCall)
                   .ArgConstraint(
                       ArgumentCondition(0, WithinRange, Range(0, IntMax))));

    // int dup2(int fildes1, int filedes2);
    addToFunctionSummaryMap(
        "dup2",
        Summary(ArgTypes{IntTy, IntTy}, RetType{IntTy}, NoEvalCall)
            .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, IntMax)))
            .ArgConstraint(
                ArgumentCondition(1, WithinRange, Range(0, IntMax))));

    /*
    // void FD_CLR(int fd, fd_set *set);
    addToFunctionSummaryMap("FD_CLR",
    Summary(ArgTypes{IntTy,Fd_setPtrTy}, RetType{VoidTy}, NoEvalCall)
    .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    .ArgConstraint(NotNull(ArgNo(1)))
    );

    // int FD_ISSET(int fd, fd_set *set);
    addToFunctionSummaryMap("FD_ISSET",
    Summary(ArgTypes{IntTy,Fd_setPtrTy}, RetType{IntTy}, NoEvalCall)
    .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    .ArgConstraint(NotNull(ArgNo(1)))
    );

    // void FD_SET(int fd, fd_set *set);
    addToFunctionSummaryMap("FD_SET",
    Summary(ArgTypes{IntTy,Fd_setPtrTy}, RetType{VoidTy}, NoEvalCall)
    .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    .ArgConstraint(NotNull(ArgNo(1)))
    );

    // void FD_ZERO(fd_set *set);
    addToFunctionSummaryMap("FD_ZERO",
    Summary(ArgTypes{Fd_setPtrTy}, RetType{VoidTy}, NoEvalCall)
    .ArgConstraint(NotNull(ArgNo(0)))
    );
    */

    // int fdatasync(int fildes);
    addToFunctionSummaryMap(
        "fdatasync", Summary(ArgTypes{IntTy}, RetType{IntTy}, NoEvalCall)
                         .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                          Range(0, IntMax))));

    // int fnmatch(const char *pattern, const char *string, int flags);
    addToFunctionSummaryMap(
        "fnmatch", Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy, IntTy},
                           RetType{IntTy}, EvalCallAsPure)
                       .ArgConstraint(NotNull(ArgNo(0)))
                       .ArgConstraint(NotNull(ArgNo(1))));

    // int fsync(int fildes);
    addToFunctionSummaryMap(
        "fsync", Summary(ArgTypes{IntTy}, RetType{IntTy}, NoEvalCall)
                     .ArgConstraint(
                         ArgumentCondition(0, WithinRange, Range(0, IntMax))));

    Optional<QualType> Off_tTy = lookupType("off_t", ACtx);

    if (Off_tTy)
      // int truncate(const char *path, off_t length);
      addToFunctionSummaryMap("truncate",
                              Summary(ArgTypes{ConstCharPtrTy, *Off_tTy},
                                      RetType{IntTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

    // FIXME This is linux only
    //// int flock(int fd, int operation);
    // addToFunctionSummaryMap("flock",
    // Summary(ArgTypes{IntTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, IntMax)))
    //);

    // int symlink(const char *oldpath, const char *newpath);
    addToFunctionSummaryMap("symlink",
                            Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy},
                                    RetType{IntTy}, NoEvalCall)
                                .ArgConstraint(NotNull(ArgNo(0)))
                                .ArgConstraint(NotNull(ArgNo(1))));

    // int symlinkat(const char *oldpath, int newdirfd, const char *newpath);
    addToFunctionSummaryMap(
        "symlinkat",
        Summary(ArgTypes{ConstCharPtrTy, IntTy, ConstCharPtrTy}, RetType{IntTy},
                NoEvalCall)
            .ArgConstraint(NotNull(ArgNo(0)))
            .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, IntMax)))
            .ArgConstraint(NotNull(ArgNo(2))));

    if (Off_tTy)
      // int lockf(int fd, int cmd, off_t len);
      addToFunctionSummaryMap(
          "lockf",
          Summary(ArgTypes{IntTy, IntTy, *Off_tTy}, RetType{IntTy}, NoEvalCall)
              .ArgConstraint(
                  ArgumentCondition(0, WithinRange, Range(0, IntMax))));

    // FIXME variadic
    //// int open(const char *pathname, int flags, mode_t mode);
    // addToFunctionSummaryMap("open",
    // Summary(ArgTypes{ConstCharPtrTy,IntTy,Mode_tTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    // FIXME variadic
    //// int openat(int dirfd, const char *pathname, int flags);    int
    ///openat(int dirfd, const char *pathname, int flags, mode_t mode);
    // addToFunctionSummaryMap("openat",
    // Summary(ArgTypes{IntTy,ConstCharPtrTy,Int);Int(intTy,ConstCharPtrTy,IntTy,Mode_tTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(1)))
    //);

    Optional<QualType> Mode_tTy = lookupType("mode_t", ACtx);

    if (Mode_tTy)
      // int creat(const char *pathname, mode_t mode);
      addToFunctionSummaryMap("creat",
                              Summary(ArgTypes{ConstCharPtrTy, *Mode_tTy},
                                      RetType{IntTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

    // unsigned int sleep(unsigned int seconds);
    addToFunctionSummaryMap(
        "sleep",
        Summary(ArgTypes{UnsignedIntTy}, RetType{UnsignedIntTy}, NoEvalCall)
            .ArgConstraint(
                ArgumentCondition(0, WithinRange, Range(0, UnsignedIntMax))));

    // FIXME POSIX.1-2008 removes the specification of usleep().
    //// int usleep(useconds_t useconds);
    // addToFunctionSummaryMap("usleep",
    // Summary(ArgTypes{Useconds_tTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0,999999)))
    //);

    Optional<QualType> DirTy = lookupType("DIR", ACtx);
    Optional<QualType> DirPtrTy;
    if (DirTy)
      DirPtrTy = ACtx.getPointerType(*DirTy);

    if (DirPtrTy)
      // int dirfd(DIR *dirp);
      addToFunctionSummaryMap(
          "dirfd", Summary(ArgTypes{*DirPtrTy}, RetType{IntTy}, NoEvalCall)
                       .ArgConstraint(NotNull(ArgNo(0))));

    // unsigned int alarm(unsigned int seconds);
    addToFunctionSummaryMap(
        "alarm",
        Summary(ArgTypes{UnsignedIntTy}, RetType{UnsignedIntTy}, NoEvalCall)
            .ArgConstraint(
                ArgumentCondition(0, WithinRange, Range(0, UnsignedIntMax))));

    // FIXME Not in POSIX.1-2001. Present on the BSDs, Solaris, and many other systems.
    //// struct rpcent *getrpcbyname(char *name);
    // addToFunctionSummaryMap("getrpcbyname",
    // Summary(ArgTypes{CharPtrTy}, RetType{StructRpcentPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // FIXME 4.3BSD; SUSv1, marked LEGACY in SUSv2, removed in POSIX.1-2001.
    //// int brk(void *addr);
    // addToFunctionSummaryMap("brk",
    // Summary(ArgTypes{VoidPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    if (DirPtrTy)
      // int closedir(DIR *dir);
      addToFunctionSummaryMap(
          "closedir", Summary(ArgTypes{*DirPtrTy}, RetType{IntTy}, NoEvalCall)
                          .ArgConstraint(NotNull(ArgNo(0))));

    // FIXME The strfry() function is unique to the GNU C Library.
    //// char *strfry(char *string);
    // addToFunctionSummaryMap("strfry",
    // Summary(ArgTypes{CharPtrTy}, RetType{CharPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // FIXME Conforming To 4.4BSD.
    //// char *strsep(char **stringp, const char *delim);
    // addToFunctionSummaryMap("strsep",
    // Summary(ArgTypes{CharPtrPtrTy,ConstCharPtrTy}, RetType{CharPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    // char *strdup(const char *s);
    addToFunctionSummaryMap("strdup", Summary(ArgTypes{ConstCharPtrTy},
                                              RetType{CharPtrTy}, NoEvalCall)
                                          .ArgConstraint(NotNull(ArgNo(0))));

    // char *strndup(const char *s, size_t n);
    addToFunctionSummaryMap(
        "strndup", Summary(ArgTypes{ConstCharPtrTy, SizeTy}, RetType{CharPtrTy},
                           NoEvalCall)
                       .ArgConstraint(NotNull(ArgNo(0)))
                       .ArgConstraint(ArgumentCondition(1, WithinRange,
                                                        Range(0, SizeMax))));

    // wchar_t *wcsdup(const wchar_t *s);
    addToFunctionSummaryMap("wcsdup", Summary(ArgTypes{ConstWchar_tPtrTy},
                                              RetType{Wchar_tPtrTy}, NoEvalCall)
                                          .ArgConstraint(NotNull(ArgNo(0))));

    // int mkstemp(char *template);
    addToFunctionSummaryMap(
        "mkstemp", Summary(ArgTypes{CharPtrTy}, RetType{IntTy}, NoEvalCall)
                       .ArgConstraint(NotNull(ArgNo(0))));

    // char *mkdtemp(char *template);
    addToFunctionSummaryMap(
        "mkdtemp", Summary(ArgTypes{CharPtrTy}, RetType{CharPtrTy}, NoEvalCall)
                       .ArgConstraint(NotNull(ArgNo(0))));

    // FIXME 4.3BSD, POSIX.1-2001.  POSIX.1-2008 removes the specification of mktemp().
    //// char *mktemp(char *template);
    // addToFunctionSummaryMap("mktemp",
    // Summary(ArgTypes{CharPtrTy}, RetType{CharPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // char *getcwd(char *buf, size_t size);
    addToFunctionSummaryMap(
        "getcwd",
        Summary(ArgTypes{CharPtrTy, SizeTy}, RetType{CharPtrTy}, NoEvalCall)
            .ArgConstraint(
                ArgumentCondition(1, WithinRange, Range(0, SizeMax))));

    if (Mode_tTy) {
      // int mkdir(const char *pathname, mode_t mode);
      addToFunctionSummaryMap("mkdir",
                              Summary(ArgTypes{ConstCharPtrTy, *Mode_tTy},
                                      RetType{IntTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

      // int mkdirat(int dirfd, const char *pathname, mode_t mode);
      addToFunctionSummaryMap(
          "mkdirat", Summary(ArgTypes{IntTy, ConstCharPtrTy, *Mode_tTy},
                             RetType{IntTy}, NoEvalCall)
                         .ArgConstraint(NotNull(ArgNo(1))));

    }

    Optional<QualType> Dev_tTy = lookupType("dev_t", ACtx);

    if (Mode_tTy && Dev_tTy) {
      // int mknod(const char *pathname, mode_t mode, dev_t dev);
      addToFunctionSummaryMap(
          "mknod", Summary(ArgTypes{ConstCharPtrTy, *Mode_tTy, *Dev_tTy},
                           RetType{IntTy}, NoEvalCall)
                       .ArgConstraint(NotNull(ArgNo(0))));

      // int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
      addToFunctionSummaryMap("mknodat", Summary(ArgTypes{IntTy, ConstCharPtrTy,
                                                          *Mode_tTy, *Dev_tTy},
                                                 RetType{IntTy}, NoEvalCall)
                                             .ArgConstraint(NotNull(ArgNo(1))));
    }

    if (Mode_tTy) {
      // int chmod(const char *path, mode_t mode);
      addToFunctionSummaryMap("chmod",
                              Summary(ArgTypes{ConstCharPtrTy, *Mode_tTy},
                                      RetType{IntTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

      // int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
      addToFunctionSummaryMap(
          "fchmodat", Summary(ArgTypes{IntTy, ConstCharPtrTy, *Mode_tTy, IntTy},
                              RetType{IntTy}, NoEvalCall)
                          // FIXME add this one arg constraint to Cppcheck
                          .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                           Range(0, IntMax)))
                          .ArgConstraint(NotNull(ArgNo(1))));

      // int fchmod(int fildes, mode_t mode);
      addToFunctionSummaryMap(
          "fchmod",
          Summary(ArgTypes{IntTy, *Mode_tTy}, RetType{IntTy}, NoEvalCall)
              .ArgConstraint(
                  ArgumentCondition(0, WithinRange, Range(0, IntMax))));
    }

    Optional<QualType> Uid_tTy = lookupType("uid_t", ACtx);
    Optional<QualType> Gid_tTy = lookupType("gid_t", ACtx);

    if (Uid_tTy && Gid_tTy) {
      // int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group,
      //              int flags);
      addToFunctionSummaryMap(
          "fchownat",
          Summary(ArgTypes{IntTy, ConstCharPtrTy, *Uid_tTy, *Gid_tTy, IntTy},
                  RetType{IntTy}, NoEvalCall)
              // FIXME Add this arg constraint to Cppcheck
              .ArgConstraint(
                  ArgumentCondition(0, WithinRange, Range(0, IntMax)))
              .ArgConstraint(NotNull(ArgNo(1))));

      // int chown(const char *path, uid_t owner, gid_t group);
      addToFunctionSummaryMap(
          "chown", Summary(ArgTypes{ConstCharPtrTy, *Uid_tTy, *Gid_tTy},
                           RetType{IntTy}, NoEvalCall)
                       .ArgConstraint(NotNull(ArgNo(0))));

      // int lchown(const char *path, uid_t owner, gid_t group);
      addToFunctionSummaryMap(
          "lchown", Summary(ArgTypes{ConstCharPtrTy, *Uid_tTy, *Gid_tTy},
                            RetType{IntTy}, NoEvalCall)
                        .ArgConstraint(NotNull(ArgNo(0))));

      // int fchown(int fildes, uid_t owner, gid_t group);
      addToFunctionSummaryMap(
          "fchown", Summary(ArgTypes{IntTy, *Uid_tTy, *Gid_tTy}, RetType{IntTy},
                            NoEvalCall)
                        .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                         Range(0, IntMax))));
    }

    // int rmdir(const char *pathname);
    addToFunctionSummaryMap(
        "rmdir", Summary(ArgTypes{ConstCharPtrTy}, RetType{IntTy}, NoEvalCall)
                     .ArgConstraint(NotNull(ArgNo(0))));

    // int chdir(const char *path);
    addToFunctionSummaryMap(
        "chdir", Summary(ArgTypes{ConstCharPtrTy}, RetType{IntTy}, NoEvalCall)
                     .ArgConstraint(NotNull(ArgNo(0))));

    // FIXME this is GNU, not posix.
    //// int chroot(const char *path);
    // addToFunctionSummaryMap("chroot",
    // Summary(ArgTypes{ConstCharPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // int link(const char *oldpath, const char *newpath);
    addToFunctionSummaryMap("link",
                            Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy},
                                    RetType{IntTy}, NoEvalCall)
                                .ArgConstraint(NotNull(ArgNo(0)))
                                .ArgConstraint(NotNull(ArgNo(1))));

    // int linkat(int fd1, const char *path1, int fd2, const char *path2,
    //            int flag);
    addToFunctionSummaryMap(
        "linkat",
        Summary(ArgTypes{IntTy, ConstCharPtrTy, IntTy, ConstCharPtrTy, IntTy},
                RetType{IntTy}, NoEvalCall)
            .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, IntMax)))
            .ArgConstraint(NotNull(ArgNo(1)))
            .ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, IntMax)))
            .ArgConstraint(NotNull(ArgNo(3))));

    // int unlink(const char *pathname);
    addToFunctionSummaryMap(
        "unlink", Summary(ArgTypes{ConstCharPtrTy}, RetType{IntTy}, NoEvalCall)
                      .ArgConstraint(NotNull(ArgNo(0))));

    // int unlinkat(int fd, const char *path, int flag);
    addToFunctionSummaryMap(
        "unlinkat",
        Summary(ArgTypes{IntTy, ConstCharPtrTy, IntTy}, RetType{IntTy},
                NoEvalCall)
            .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, IntMax)))
            .ArgConstraint(NotNull(ArgNo(1))));

    Optional<QualType> StructStatTy = lookupType("stat", ACtx);
    Optional<QualType> StructStatPtrTy, StructStatPtrRestrictTy;
    if (StructStatTy) {
      StructStatPtrTy = ACtx.getPointerType(*StructStatTy);
      StructStatPtrRestrictTy = ACtx.getLangOpts().C99
                                    ? ACtx.getRestrictType(*StructStatPtrTy)
                                    : *StructStatPtrTy;
    }

    if (StructStatPtrTy)
      // int fstat(int fd, struct stat *statbuf);
      addToFunctionSummaryMap(
          "fstat",
          Summary(ArgTypes{IntTy, *StructStatPtrTy}, RetType{IntTy}, NoEvalCall)
              .ArgConstraint(
                  ArgumentCondition(0, WithinRange, Range(0, IntMax)))
              .ArgConstraint(NotNull(ArgNo(1))));

    if (StructStatPtrRestrictTy) {
      // int stat(const char *restrict path, struct stat *restrict buf);
      addToFunctionSummaryMap(
          "stat",
          Summary(ArgTypes{ConstCharPtrRestrictTy, *StructStatPtrRestrictTy},
                  RetType{IntTy}, NoEvalCall)
              .ArgConstraint(NotNull(ArgNo(0)))
              .ArgConstraint(NotNull(ArgNo(1))));

      // int lstat(const char *restrict path, struct stat *restrict buf);
      addToFunctionSummaryMap(
          "lstat",
          Summary(ArgTypes{ConstCharPtrRestrictTy, *StructStatPtrRestrictTy},
                  RetType{IntTy}, NoEvalCall)
              .ArgConstraint(NotNull(ArgNo(0)))
              .ArgConstraint(NotNull(ArgNo(1))));

      // int fstatat(int fd, const char *restrict path,
      //             struct stat *restrict buf, int flag);
      addToFunctionSummaryMap(
          "fstatat", Summary(ArgTypes{IntTy, ConstCharPtrRestrictTy,
                                      *StructStatPtrRestrictTy, IntTy},
                             RetType{IntTy}, NoEvalCall)
                         .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                          Range(0, IntMax)))
                         .ArgConstraint(NotNull(ArgNo(1)))
                         .ArgConstraint(NotNull(ArgNo(2))));
    }

    if (DirPtrTy) {
      // DIR *opendir(const char *name);
      addToFunctionSummaryMap("opendir", Summary(ArgTypes{ConstCharPtrTy},
                                                 RetType{*DirPtrTy}, NoEvalCall)
                                             .ArgConstraint(NotNull(ArgNo(0))));

      // DIR *fdopendir(int fd);
      addToFunctionSummaryMap(
          "fdopendir", Summary(ArgTypes{IntTy}, RetType{*DirPtrTy}, NoEvalCall)
                           .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                            Range(0, IntMax))));
    }

    // int isatty(int fildes);
    addToFunctionSummaryMap(
        "isatty", Summary(ArgTypes{IntTy}, RetType{IntTy}, NoEvalCall)
                      .ArgConstraint(
                          ArgumentCondition(0, WithinRange, Range(0, IntMax))));

    if (FilePtrTy) {
      // FILE *popen(const char *command, const char *type);
      addToFunctionSummaryMap("popen",
                              Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy},
                                      RetType{*FilePtrTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0)))
                                  .ArgConstraint(NotNull(ArgNo(1))));

      // int pclose(FILE *stream);
      addToFunctionSummaryMap(
          "pclose", Summary(ArgTypes{*FilePtrTy}, RetType{IntTy}, NoEvalCall)
                        .ArgConstraint(NotNull(ArgNo(0))));
    }

    // int close(int fildes);
    addToFunctionSummaryMap(
        "close", Summary(ArgTypes{IntTy}, RetType{IntTy}, NoEvalCall)
                     .ArgConstraint(
                         ArgumentCondition(0, WithinRange, Range(0, IntMax))));

    // long fpathconf(int fildes, int name);
    addToFunctionSummaryMap(
        "fpathconf",
        Summary(ArgTypes{IntTy, IntTy}, RetType{LongTy}, NoEvalCall)
            .ArgConstraint(
                ArgumentCondition(0, WithinRange, Range(0, IntMax))));

    // long pathconf(const char *path, int name);
    addToFunctionSummaryMap("pathconf", Summary(ArgTypes{ConstCharPtrTy, IntTy},
                                                RetType{LongTy}, NoEvalCall)
                                            .ArgConstraint(NotNull(ArgNo(0))));

    if (FilePtrTy)
      // FILE *fdopen(int fd, const char *mode);
      addToFunctionSummaryMap(
          "fdopen", Summary(ArgTypes{IntTy, ConstCharPtrTy},
                            RetType{*FilePtrTy}, NoEvalCall)
                        .ArgConstraint(
                            ArgumentCondition(0, WithinRange, Range(0, IntMax)))
                        .ArgConstraint(NotNull(ArgNo(1))));

    if (DirPtrTy) {
      // void rewinddir(DIR *dir);
      addToFunctionSummaryMap(
          "rewinddir", Summary(ArgTypes{*DirPtrTy}, RetType{VoidTy}, NoEvalCall)
                           .ArgConstraint(NotNull(ArgNo(0))));

      // void seekdir(DIR *dirp, long loc);
      addToFunctionSummaryMap("seekdir", Summary(ArgTypes{*DirPtrTy, LongTy},
                                                 RetType{VoidTy}, NoEvalCall)
                                             .ArgConstraint(NotNull(ArgNo(0))));
    }

    // int rand_r(unsigned int *seedp);
    addToFunctionSummaryMap("rand_r", Summary(ArgTypes{UnsignedIntPtrTy},
                                              RetType{IntTy}, NoEvalCall)
                                          .ArgConstraint(NotNull(ArgNo(0))));

    // int strcasecmp(const char *s1, const char *s2);
    addToFunctionSummaryMap("strcasecmp",
                            Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy},
                                    RetType{IntTy}, EvalCallAsPure)
                                .ArgConstraint(NotNull(ArgNo(0)))
                                .ArgConstraint(NotNull(ArgNo(1))));

    // int strncasecmp(const char *s1, const char *s2, size_t n);
    addToFunctionSummaryMap(
        "strncasecmp", Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy, SizeTy},
                               RetType{IntTy}, EvalCallAsPure)
                           .ArgConstraint(NotNull(ArgNo(0)))
                           .ArgConstraint(NotNull(ArgNo(1)))
                           .ArgConstraint(ArgumentCondition(
                               2, WithinRange, Range(0, SizeMax))));

    if (FilePtrTy && Off_tTy) {

      // int fileno(FILE *stream);
      addToFunctionSummaryMap(
          "fileno", Summary(ArgTypes{*FilePtrTy}, RetType{IntTy}, NoEvalCall)
                        .ArgConstraint(NotNull(ArgNo(0))));

      // int fseeko(FILE *stream, off_t offset, int whence);
      addToFunctionSummaryMap("fseeko",
                              Summary(ArgTypes{*FilePtrTy, *Off_tTy, IntTy},
                                      RetType{IntTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

      // off_t ftello(FILE *stream);
      addToFunctionSummaryMap(
          "ftello", Summary(ArgTypes{*FilePtrTy}, RetType{*Off_tTy}, NoEvalCall)
                        .ArgConstraint(NotNull(ArgNo(0))));
    }

    Optional<RangeInt> Off_tMax;
    if (Off_tTy) {
      Off_tMax = BVF.getMaxValue(*Off_tTy).getLimitedValue();

      // void *mmap(void *addr, size_t length, int prot, int flags, int fd,
      // off_t offset);
      addToFunctionSummaryMap(
          "mmap",
          Summary(ArgTypes{VoidPtrTy, SizeTy, IntTy, IntTy, IntTy, *Off_tTy},
                  RetType{VoidPtrTy}, NoEvalCall)
              .ArgConstraint(
                  ArgumentCondition(1, WithinRange, Range(1, SizeMax)))
              .ArgConstraint(
                  ArgumentCondition(4, WithinRange, Range(0, *Off_tMax))));
    }

    Optional<QualType> Off64_tTy = lookupType("off64_t", ACtx);
    Optional<RangeInt> Off64_tMax;
    if (Off64_tTy) {
      Off64_tMax = BVF.getMaxValue(*Off_tTy).getLimitedValue();
      // void *mmap64(void *addr, size_t length, int prot, int flags, int fd,
      // off64_t offset);
      addToFunctionSummaryMap(
          "mmap64",
          Summary(ArgTypes{VoidPtrTy, SizeTy, IntTy, IntTy, IntTy, *Off64_tTy},
                  RetType{VoidPtrTy}, NoEvalCall)
              .ArgConstraint(
                  ArgumentCondition(1, WithinRange, Range(1, SizeMax)))
              .ArgConstraint(
                  ArgumentCondition(4, WithinRange, Range(0, *Off64_tMax))));
    }

    // int pipe(int fildes[2]);
    addToFunctionSummaryMap(
        "pipe", Summary(ArgTypes{IntPtrTy}, RetType{IntTy}, NoEvalCall)
                    .ArgConstraint(NotNull(ArgNo(0))));

    if (Off_tTy)
      // off_t lseek(int fildes, off_t offset, int whence);
      addToFunctionSummaryMap(
          "lseek", Summary(ArgTypes{IntTy, *Off_tTy, IntTy}, RetType{*Off_tTy},
                           NoEvalCall)
                       .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                        Range(0, IntMax))));

    Optional<QualType> Ssize_tTy = lookupType("ssize_t", ACtx);

    if (Ssize_tTy) {
      // ssize_t readlink(const char *restrict path, char *restrict buf,
      //                  size_t bufsize);
      addToFunctionSummaryMap(
          "readlink",
          Summary(ArgTypes{ConstCharPtrRestrictTy, CharPtrRestrictTy, SizeTy},
                  RetType{*Ssize_tTy}, NoEvalCall)
              .ArgConstraint(NotNull(ArgNo(0)))
              .ArgConstraint(NotNull(ArgNo(1)))
              .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1),
                                        /*BufSize=*/ArgNo(2)))
              .ArgConstraint(
                  ArgumentCondition(2, WithinRange, Range(0, SizeMax))));

      // ssize_t readlinkat(int fd, const char *restrict path,
      //                    char *restrict buf, size_t bufsize);
      addToFunctionSummaryMap(
          "readlinkat", Summary(ArgTypes{IntTy, ConstCharPtrRestrictTy,
                                         CharPtrRestrictTy, SizeTy},
                                RetType{*Ssize_tTy}, NoEvalCall)
                            // FIXME add this constraint back to Cppcheck
                            .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                             Range(0, IntMax)))
                            .ArgConstraint(NotNull(ArgNo(1)))
                            .ArgConstraint(NotNull(ArgNo(2)))
                            .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(2),
                                                      /*BufSize=*/ArgNo(3)))
                            .ArgConstraint(ArgumentCondition(
                                3, WithinRange, Range(0, SizeMax))));
    }

    // int renameat(int olddirfd, const char *oldpath, int newdirfd, const char
    // *newpath);
    addToFunctionSummaryMap("renameat", Summary(ArgTypes{IntTy, ConstCharPtrTy,
                                                         IntTy, ConstCharPtrTy},
                                                RetType{IntTy}, NoEvalCall)
                                            .ArgConstraint(NotNull(ArgNo(1)))
                                            .ArgConstraint(NotNull(ArgNo(3))));

    // char *realpath(const char *restrict file_name,
    //                char *restrict resolved_name);
    addToFunctionSummaryMap(
        "realpath", Summary(ArgTypes{ConstCharPtrRestrictTy, CharPtrRestrictTy},
                            RetType{CharPtrTy}, NoEvalCall)
                        .ArgConstraint(NotNull(ArgNo(0))));

    QualType CharPtrConstPtr = ACtx.getPointerType(CharPtrTy.withConst());

    // int execv(const char *path, char *const argv[]);
    addToFunctionSummaryMap("execv",
                            Summary(ArgTypes{ConstCharPtrTy, CharPtrConstPtr},
                                    RetType{IntTy}, NoEvalCall)
                                .ArgConstraint(NotNull(ArgNo(0))));

    // int execvp(const char *file, char *const argv[]);
    addToFunctionSummaryMap("execvp",
                            Summary(ArgTypes{ConstCharPtrTy, CharPtrConstPtr},
                                    RetType{IntTy}, NoEvalCall)
                                .ArgConstraint(NotNull(ArgNo(0))));

    // int getopt(int argc, char * const argv[], const char *optstring);
    addToFunctionSummaryMap(
        "getopt",
        Summary(ArgTypes{IntTy, CharPtrConstPtr, ConstCharPtrTy},
                RetType{IntTy}, NoEvalCall)
            .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, IntMax)))
            .ArgConstraint(NotNull(ArgNo(1)))
            .ArgConstraint(NotNull(ArgNo(2))));

    // =================== NETWORK ===================

    // FIXME sendfile() is a new feature in Linux 2.2. The include file
    // <sys/sendfile.h> is present since glibc 2.1. Not specified in
    // POSIX.1-2001, or other standards.
    //// ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
    // addToFunctionSummaryMap("sendfile",
    // Summary(ArgTypes{IntTy,IntTy,Off_tPtrTy,SizeTy}, RetType{Ssize_tTy},
    // NoEvalCall) .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0,
    // Max))) .ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
    //.ArgConstraint(ArgumentCondition(3, WithinRange, Range(1, Max)))
    //);

    // FIXME merge this with the summary above.
    //// ssize_t read(int fd, void *buf, size_t count);
    // addToFunctionSummaryMap("read",
    // Summary(ArgTypes{IntTy,VoidPtrTy,SizeTy}, RetType{Ssize_tTy},
    // NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    // FIXME merge this with the summary above.
    //// ssize_t write(int fildes, const void *buf, size_t nbyte);
    // addToFunctionSummaryMap("write",
    // Summary(ArgTypes{IntTy,ConstVoidPtrTy,SizeTy}, RetType{Ssize_tTy},
    // NoEvalCall) .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0,
    // Max))) .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1),
    ///*BufSize=*/ArgNo(2))) .ArgConstraint(ArgumentCondition(2, WithinRange,
    // Range(0, Max)))
    //);

    if (Ssize_tTy)
      // ssize_t recv(int sockfd, void *buf, size_t len, int flags);
      addToFunctionSummaryMap(
          "recv", Summary(ArgTypes{IntTy, VoidPtrTy, SizeTy, IntTy},
                          RetType{*Ssize_tTy}, NoEvalCall)
                      .ArgConstraint(
                          ArgumentCondition(0, WithinRange, Range(0, IntMax)))
                      .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1),
                                                /*BufSize=*/ArgNo(2))));

    Optional<QualType> StructMsghdrTy = lookupType("msghdr", ACtx);
    Optional<QualType> StructMsghdrPtrTy, ConstStructMsghdrPtrTy;
    if (StructMsghdrTy) {
      StructMsghdrPtrTy = ACtx.getPointerType(*StructMsghdrTy);
      ConstStructMsghdrPtrTy = ACtx.getPointerType(StructMsghdrTy->withConst());
    }

    if (Ssize_tTy && StructMsghdrPtrTy)
      // ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
      addToFunctionSummaryMap(
          "recvmsg", Summary(ArgTypes{IntTy, *StructMsghdrPtrTy, IntTy},
                             RetType{*Ssize_tTy}, NoEvalCall)
                         .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                          Range(0, IntMax))));

    if (Ssize_tTy && ConstStructMsghdrPtrTy)
      // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
      addToFunctionSummaryMap(
          "sendmsg", Summary(ArgTypes{IntTy, *ConstStructMsghdrPtrTy, IntTy},
                             RetType{*Ssize_tTy}, NoEvalCall)
                         .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                          Range(0, IntMax))));

    Optional<QualType> StructProtoentTy = lookupType("protoent", ACtx);
    Optional<QualType> StructProtoentPtrTy;
    if (StructProtoentTy)
      StructProtoentPtrTy = ACtx.getPointerType(*StructProtoentTy);

    if (StructProtoentPtrTy)
      // struct protoent *getprotobyname(const char *name);
      addToFunctionSummaryMap("getprotobyname",
                              Summary(ArgTypes{ConstCharPtrTy},
                                      RetType{*StructProtoentPtrTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

    Optional<QualType> StructServentTy = lookupType("servent", ACtx);
    Optional<QualType> StructServentPtrTy;
    if (StructServentTy)
      StructServentPtrTy = ACtx.getPointerType(*StructServentTy);

    if (StructServentPtrTy)
      // struct servent *getservbyname(const char *name, const char *proto);
      addToFunctionSummaryMap("getservbyname",
                              Summary(ArgTypes{ConstCharPtrTy, ConstCharPtrTy},
                                      RetType{*StructServentPtrTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

    Optional<QualType> StructNetentTy = lookupType("netent", ACtx);
    Optional<QualType> StructNetentPtrTy;
    if (StructNetentTy)
      StructNetentPtrTy = ACtx.getPointerType(*StructNetentTy);

    if (StructNetentPtrTy)
      // struct netent *getnetbyname(const char *name);
      addToFunctionSummaryMap("getnetbyname",
                              Summary(ArgTypes{ConstCharPtrTy},
                                      RetType{*StructNetentPtrTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

    Optional<QualType> StructHostentTy = lookupType("hostent", ACtx);
    Optional<QualType> StructHostentPtrTy;
    if (StructHostentTy)
      StructHostentPtrTy = ACtx.getPointerType(*StructHostentTy);

    if (StructHostentPtrTy)
      // struct hostent *gethostbyname(const char *name);
      addToFunctionSummaryMap("gethostbyname",
                              Summary(ArgTypes{ConstCharPtrTy},
                                      RetType{*StructHostentPtrTy}, NoEvalCall)
                                  .ArgConstraint(NotNull(ArgNo(0))));

    // FIXME POSIX.1-2008 removes the specifications of gethostbyname(),
    // gethostbyaddr(), and h_errno, recommending the use of getaddrinfo(3)
    // and getnameinfo(3) instead.
    //// struct hostent *gethostbyname2(const char *name, int af);
    // addToFunctionSummaryMap("gethostbyname2",
    // Summary(ArgTypes{ConstCharPtrTy,IntTy}, RetType{StructHostentPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);
    //// struct hostent *gethostbyaddr(const void *addr, socklen_t len, int
    /// type);
    // addToFunctionSummaryMap("gethostbyaddr",
    // Summary(ArgTypes{ConstVoidPtrTy,Socklen_tTy,IntTy},
    // RetType{StructHostentPtrTy}, NoEvalCall)
    // .ArgConstraint(NotNull(ArgNo(0)))
    //);

    Optional<QualType> Socklen_tTy = lookupType("socklen_t", ACtx);
    Optional<QualType> Socklen_tPtrRestrictTy;
    Optional<RangeInt> Socklen_tMax;
    if (Socklen_tTy) {
      Socklen_tPtrRestrictTy =
          ACtx.getLangOpts().C99
              ? ACtx.getRestrictType(ACtx.getPointerType(*Socklen_tTy))
              : ACtx.getPointerType(*Socklen_tTy);
      Socklen_tMax = BVF.getMaxValue(*Socklen_tTy).getLimitedValue();
    }

    if (Socklen_tTy)
      // int setsockopt(int socket, int level, int option_name,
      //                const void *option_value, socklen_t option_len);
      addToFunctionSummaryMap(
          "setsockopt",
          Summary(ArgTypes{IntTy, IntTy, IntTy, ConstVoidPtrTy, *Socklen_tTy},
                  RetType{IntTy}, NoEvalCall)
              .ArgConstraint(NotNull(ArgNo(3)))
              .ArgConstraint(
                  BufferSize(/*Buffer=*/ArgNo(3), /*BufSize=*/ArgNo(4)))
              .ArgConstraint(
                  ArgumentCondition(4, WithinRange, Range(0, *Socklen_tMax))));

    if (Socklen_tPtrRestrictTy)
      // int getsockopt(int socket, int level, int option_name,
      //                void *restrict option_value,
      //                socklen_t *restrict option_len);
      addToFunctionSummaryMap(
          "getsockopt", Summary(ArgTypes{IntTy, IntTy, IntTy, VoidPtrRestrictTy,
                                         *Socklen_tPtrRestrictTy},
                                RetType{IntTy}, NoEvalCall)
                            .ArgConstraint(NotNull(ArgNo(3)))
                            .ArgConstraint(NotNull(ArgNo(4))));

    //// ssize_t send(int sockfd, const void *buf, size_t len, int flags);
    // addToFunctionSummaryMap("send",
    // Summary(ArgTypes{IntTy,ConstVoidPtrTy,SizeTy,IntTy},
    // RetType{Ssize_tTy}, NoEvalCall) .ArgConstraint(ArgumentCondition(0,
    // WithinRange, Range(0,
    // Max))) .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1),
    ///*BufSize=*/ArgNo(2)))
    //);

    //// ssize_t sendto(int socket, const void *message, size_t length,
    //       int flags, const struct sockaddr *dest_addr,
    //              socklen_t dest_len);
    // addToFunctionSummaryMap("sendto",
    // Summary(ArgTypes{}, RetType{}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //);

    Optional<QualType> StructUtimbufTy = lookupType("utimbuf", ACtx);
    Optional<QualType> StructUtimbufPtrTy;
    if (StructUtimbufTy)
      StructUtimbufPtrTy = ACtx.getPointerType(*StructUtimbufTy);

    if (StructUtimbufPtrTy)
      // int utime(const char *filename, struct utimbuf *buf);
      addToFunctionSummaryMap(
          "utime", Summary(ArgTypes{ConstCharPtrTy, *StructUtimbufPtrTy},
                           RetType{IntTy}, NoEvalCall)
                       .ArgConstraint(NotNull(ArgNo(0))));

    Optional<QualType> StructTimespecTy = lookupType("timespec", ACtx);
    Optional<QualType> ConstStructTimespecPtrTy;
    if (StructTimespecTy)
      ConstStructTimespecPtrTy =
          ACtx.getPointerType(StructTimespecTy->withConst());

    if (ConstStructTimespecPtrTy) {
      // int futimens(int fd, const struct timespec times[2]);
      addToFunctionSummaryMap(
          "futimens", Summary(ArgTypes{IntTy, *ConstStructTimespecPtrTy},
                              RetType{IntTy}, NoEvalCall)
                          .ArgConstraint(ArgumentCondition(0, WithinRange,
                                                           Range(0, IntMax))));

      // int utimensat(int dirfd, const char *pathname,
      //               const struct timespec times[2], int flags);
      addToFunctionSummaryMap(
          "utimensat", Summary(ArgTypes{IntTy, ConstCharPtrTy,
                                        *ConstStructTimespecPtrTy, IntTy},
                               RetType{IntTy}, NoEvalCall)
                           .ArgConstraint(NotNull(ArgNo(1))));
    }

    Optional<QualType> StructTimevalTy = lookupType("timeval", ACtx);
    Optional<QualType> ConstStructTimevalPtrTy;
    if (StructTimevalTy)
      ConstStructTimevalPtrTy =
          ACtx.getPointerType(StructTimevalTy->withConst());

    if (ConstStructTimevalPtrTy)
      // int utimes(const char *filename, const struct timeval times[2]);
      addToFunctionSummaryMap(
          "utimes", Summary(ArgTypes{ConstCharPtrTy, *ConstStructTimevalPtrTy},
                            RetType{IntTy}, NoEvalCall)
                        .ArgConstraint(NotNull(ArgNo(0))));

    //// int munmap(void *addr, size_t length);
    // addToFunctionSummaryMap("munmap",
    // Summary(ArgTypes{VoidPtrTy,SizeTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(1, Max)))
    //);

    //// int fcntl(int fd, int cmd, ... [> arg <] );
    // addToFunctionSummaryMap("fcntl",
    // Summary(ArgTypes{IntTy,IntTy,.../PtrArg*/Ty}, RetType{IntTy},
    // NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// int ioctl(int fd, unsigned long request, ...);
    // addToFunctionSummaryMap("ioctl",
    // Summary(ArgTypes{IntTy,UnsignedLongTy,...Ty}, RetType{IntTy},
    // NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// int socketpair(int domain, int type, int protocol, int sv[2]);
    // addToFunctionSummaryMap("socketpair",
    // Summary(ArgTypes{IntTy,IntTy,IntTy,IntSv[2]Ty}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(3)))
    //);

    // FIXME getwd() is present in POSIX.1-2001, but marked LEGACY. POSIX.1-2008 removes the specification of getwd()
    //// char *getwd(char *path_name);
    // addToFunctionSummaryMap("getwd",
    // Summary(ArgTypes{CharPtrTy}, RetType{CharPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int mq_notify(mqd_t, const struct sigevent *);
    // addToFunctionSummaryMap("mq_notify",
    // Summary(ArgTypes{Ty,ConstStructSigeventPtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
    /// unsigned *msg_prio);
    // addToFunctionSummaryMap("mq_receive",
    // Summary(ArgTypes{Mqd_tTy,CharPtrTy,SizeTy,UnsignedPtrTy},
    // RetType{Ssize_tTy}, NoEvalCall)
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// int mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
    /// unsigned msg_prio);
    // addToFunctionSummaryMap("mq_send",
    // Summary(ArgTypes{Mqd_tTy,ConstCharPtrTy,SizeTy,UnsignedTy},
    // RetType{IntTy}, NoEvalCall)
    // .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1),
    ///*BufSize=*/ArgNo(2)))
    //);

    //// ssize_t mq_timedreceive(mqd_t mqdes, char *restrict msg_ptr, size_t
    /// msg_len, unsigned *restrict msg_prio, const struct timespec *restrict
    /// abstime);
    // addToFunctionSummaryMap("mq_timedreceive",
    // Summary(ArgTypes{Mqd_tTy,CharPtrRestrictTy,SizeTy,UnsignedPtrRestrictTy,ConstStructTimespecPtrRestrictTy},
    // RetType{Ssize_tTy}, NoEvalCall)
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //);

    //// int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
    /// unsigned msg_prio, const struct timespec *abstime);
    // addToFunctionSummaryMap("mq_timedsend",
    // Summary(ArgTypes{Mqd_tTy,ConstCharPtrTy,SizeTy,UnsignedTy,ConstStructTimespecPtrTy},
    // RetType{IntTy}, NoEvalCall)
    // .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1),
    ///*BufSize=*/ArgNo(2)))
    //);

    //// int mq_unlink(const char *name);
    // addToFunctionSummaryMap("mq_unlink",
    // Summary(ArgTypes{ConstCharPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int dbm_clearerr(DBM *db);
    // addToFunctionSummaryMap("dbm_clearerr",
    // Summary(ArgTypes{DbmPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// void dbm_close(DBM *db);
    // addToFunctionSummaryMap("dbm_close",
    // Summary(ArgTypes{DbmPtrTy}, RetType{VoidTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int dbm_delete(DBM *db, datum key);
    // addToFunctionSummaryMap("dbm_delete",
    // Summary(ArgTypes{DbmPtrTy,DatumTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int dbm_error(DBM *db);
    // addToFunctionSummaryMap("dbm_error",
    // Summary(ArgTypes{DbmPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// datum dbm_fetch(DBM *db, datum key);
    // addToFunctionSummaryMap("dbm_fetch",
    // Summary(ArgTypes{DbmPtrTy,DatumTy}, RetType{DatumTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// datum dbm_firstkey(DBM *db);
    // addToFunctionSummaryMap("dbm_firstkey",
    // Summary(ArgTypes{DbmPtrTy}, RetType{DatumTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// datum dbm_nextkey(DBM *db);
    // addToFunctionSummaryMap("dbm_nextkey",
    // Summary(ArgTypes{DbmPtrTy}, RetType{DatumTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// DBM *dbm_open(const char *file, int open_flags, mode_t file_mode);
    // addToFunctionSummaryMap("dbm_open",
    // Summary(ArgTypes{ConstCharPtrTy,IntTy,Mode_tTy}, RetType{DbmPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int dbm_store(DBM *db, datum key, datum content, int store_mode);
    // addToFunctionSummaryMap("dbm_store",
    // Summary(ArgTypes{DbmPtrTy,DatumTy,DatumTy,IntTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// void freeaddrinfo(struct addrinfo *ai);
    // addToFunctionSummaryMap("freeaddrinfo",
    // Summary(ArgTypes{StructAddrinfoPtrTy}, RetType{VoidTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int getnameinfo(const struct sockaddr *restrict sa, socklen_t salen,
    //       char *restrict node, socklen_t nodelen, char *restrict service,
    //              socklen_t servicelen, int flags);
    // addToFunctionSummaryMap("getnameinfo",
    // Summary(ArgTypes{}, RetType{}, NoEvalCall)
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(0), /*BufSize=*/ArgNo(1)))
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(2), /*BufSize=*/ArgNo(3)))
    //.ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(4), /*BufSize=*/ArgNo(5)))
    //.ArgConstraint(ArgumentCondition(5, WithinRange, Range(0, Max)))
    //);

    //// int uname(struct utsname *buf);
    // addToFunctionSummaryMap("uname",
    // Summary(ArgTypes{StructUtsnamePtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// char *strtok_r(char *str, const char *delim, char **saveptr);
    // addToFunctionSummaryMap("strtok_r",
    // Summary(ArgTypes{CharPtrTy,ConstCharPtrTy,CharPtrPtrTy},
    // RetType{CharPtrTy}, EvalCallAsPure) .ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(NotNull(ArgNo(2)))
    //);

    //// int getpwnam_r(const char *name, struct passwd *pwd, char *buffer,
    /// size_t bufsize, struct passwd **result);
    // addToFunctionSummaryMap("getpwnam_r",
    // Summary(ArgTypes{ConstCharPtrTy,StructPasswdPtrTy,CharPtrTy,SizeTy,StructPasswdPtrPtrTy},
    // RetType{IntTy}, NoEvalCall)
    // .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(2),
    ///*BufSize=*/ArgNo(3))) .ArgConstraint(ArgumentCondition(3, WithinRange,
    // Range(0, Max)))
    //);

    //// int getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t
    /// bufsize, struct passwd **result);
    // addToFunctionSummaryMap("getpwuid_r",
    // Summary(ArgTypes{Uid_tTy,StructPasswdPtrTy,CharPtrTy,SizeTy,StructPasswdPtrPtrTy},
    // RetType{IntTy}, NoEvalCall)
    // .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(2),
    ///*BufSize=*/ArgNo(3))) .ArgConstraint(ArgumentCondition(3, WithinRange,
    // Range(0, Max)))
    //);

    //// nl_catd catopen(const char *name, int oflag);
    // addToFunctionSummaryMap("catopen",
    // Summary(ArgTypes{ConstCharPtrTy,IntTy}, RetType{Nl_catdTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int regcomp(regex_t *restrict preg, const char *restrict pattern, int
    /// cflags);
    // addToFunctionSummaryMap("regcomp",
    // Summary(ArgTypes{Regex_tPtrRestrictTy,ConstCharPtrRestrictTy,IntTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// size_t regerror(int errcode, const regex_t *restrict preg, char
    ///*restrict errbuf, size_t errbuf_size);
    // addToFunctionSummaryMap("regerror",
    // Summary(ArgTypes{IntTy,ConstRegex_tPtrRestrictTy,CharPtrRestrictTy,SizeTy},
    // RetType{SizeTy}, NoEvalCall)
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(2), /*BufSize=*/ArgNo(3)))
    //.ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max)))
    //);

    //// int regexec(const regex_t *restrict preg, const char *restrict
    /// string, size_t nmatch, regmatch_t pmatch[restrict], int eflags);
    // addToFunctionSummaryMap("regexec",
    // Summary(ArgTypes{ConstRegex_tPtrRestrictTy,ConstCharPtrRestrictTy,SizeTy,Regmatch_tPmatch[restrict]Ty,IntTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// void regfree(regex_t *preg);
    // addToFunctionSummaryMap("regfree",
    // Summary(ArgTypes{Regex_tPtrTy}, RetType{VoidTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int sched_getparam(pid_t pid, struct sched_param *param);
    // addToFunctionSummaryMap("sched_getparam",
    // Summary(ArgTypes{Pid_tTy,StructSched_paramPtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0,
    // Max))) .ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int sched_getscheduler(pid_t pid);
    // addToFunctionSummaryMap("sched_getscheduler",
    // Summary(ArgTypes{Pid_tTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// int sched_rr_get_interval(pid_t pid, struct timespec *interval);
    // addToFunctionSummaryMap("sched_rr_get_interval",
    // Summary(ArgTypes{Pid_tTy,StructTimespecPtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int sched_setparam(pid_t pid, const struct sched_param *param);
    // addToFunctionSummaryMap("sched_setparam",
    // Summary(ArgTypes{Pid_tTy,ConstStructSched_paramPtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0,
    // Max)))
    //);

    //// int sched_setscheduler(pid_t pid, int policy, const struct
    /// sched_param *param);
    // addToFunctionSummaryMap("sched_setscheduler",
    // Summary(ArgTypes{Pid_tTy,IntTy,ConstStructSched_paramPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(ArgumentCondition(0,
    // WithinRange, Range(0, Max)))
    //);

    //// char *ecvt(double value, int ndigit, int *restrict decpt, int
    ///*restrict sign);
    // addToFunctionSummaryMap("ecvt",
    // Summary(ArgTypes{DoubleTy,IntTy,IntPtrRestrictTy,IntPtrRestrictTy},
    // RetType{CharPtrTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(2)))
    //.ArgConstraint(NotNull(ArgNo(3)))
    //);

    //// char *fcvt(double value, int ndigit, int *restrict decpt, int
    ///*restrict sign);
    // addToFunctionSummaryMap("fcvt",
    // Summary(ArgTypes{DoubleTy,IntTy,IntPtrRestrictTy,IntPtrRestrictTy},
    // RetType{CharPtrTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(2)))
    //.ArgConstraint(NotNull(ArgNo(3)))
    //);

    //// char *gcvt(double value, int ndigit, char *buf);
    // addToFunctionSummaryMap("gcvt",
    // Summary(ArgTypes{DoubleTy,IntTy,CharPtrTy}, RetType{CharPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(2)))
    //);

    //// int nanosleep(const struct timespec *rqtp, struct timespec *rmtp);
    // addToFunctionSummaryMap("nanosleep",
    // Summary(ArgTypes{ConstStructTimespecPtrTy,StructTimespecPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// void setkey(const char *key);
    // addToFunctionSummaryMap("setkey",
    // Summary(ArgTypes{ConstCharPtrTy}, RetType{VoidTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// char *getpass(const char *prompt);
    // addToFunctionSummaryMap("getpass",
    // Summary(ArgTypes{ConstCharPtrTy}, RetType{CharPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int putenv(char *string);
    // addToFunctionSummaryMap("putenv",
    // Summary(ArgTypes{CharPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int setenv(const char *envname, const char *envval, int overwrite);
    // addToFunctionSummaryMap("setenv",
    // Summary(ArgTypes{ConstCharPtrTy,ConstCharPtrTy,IntTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int unsetenv(const char *name);
    // addToFunctionSummaryMap("unsetenv",
    // Summary(ArgTypes{ConstCharPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// struct tm * localtime(const time_t *tp);
    // addToFunctionSummaryMap("localtime",
    // Summary(ArgTypes{ConstTime_tPtrTy}, RetType{StructTmPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// struct tm *localtime_r(const time_t *timep, struct tm *result);
    // addToFunctionSummaryMap("localtime_r",
    // Summary(ArgTypes{ConstTime_tPtrTy,StructTmPtrTy},
    // RetType{StructTmPtrTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// struct dirent *readdir(DIR *dirp);
    // addToFunctionSummaryMap("readdir",
    // Summary(ArgTypes{DirPtrTy}, RetType{StructDirentPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int readdir_r(DIR *dirp, struct dirent *entry, struct dirent
    ///**result);
    // addToFunctionSummaryMap("readdir_r",
    // Summary(ArgTypes{DirPtrTy,StructDirentPtrTy,StructDirentPtrPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(NotNull(ArgNo(2)))
    //);

    //// char *asctime_r(const struct tm *tm, char *buf);
    // addToFunctionSummaryMap("asctime_r",
    // Summary(ArgTypes{ConstStructTmPtrTy,CharPtrTy}, RetType{CharPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// char *ctime_r(const time_t *timep, char *buf);
    // addToFunctionSummaryMap("ctime_r",
    // Summary(ArgTypes{ConstTime_tPtrTy,CharPtrTy}, RetType{CharPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// struct tm *gmtime_r(const time_t *timep, struct tm *result);
    // addToFunctionSummaryMap("gmtime_r",
    // Summary(ArgTypes{ConstTime_tPtrTy,StructTmPtrTy},
    // RetType{StructTmPtrTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// struct tm * gmtime(const time_t *tp);
    // addToFunctionSummaryMap("gmtime",
    // Summary(ArgTypes{ConstTime_tPtrTy}, RetType{StructTmPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int clock_gettime(clockid_t clock_id, struct timespec *tp);
    // addToFunctionSummaryMap("clock_gettime",
    // Summary(ArgTypes{Clockid_tTy,StructTimespecPtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// void makecontext(ucontext_t *ucp, void (*func)(), int argc, ...);
    // addToFunctionSummaryMap("makecontext",
    // Summary(ArgTypes{Ucontext_tPtrTy,Void(*)()Ty,IntTy,...Ty},
    // RetType{VoidTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// void swapcontext(ucontext_t *restrict oucp, const ucontext_t
    ///*restrict ucp);
    // addToFunctionSummaryMap("swapcontext",
    // Summary(ArgTypes{Ucontext_tPtrRestrictTy,ConstUcontext_tPtrRestrictTy},
    // RetType{VoidTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// void getcontext(ucontext_t *ucp);
    // addToFunctionSummaryMap("getcontext",
    // Summary(ArgTypes{Ucontext_tPtrTy}, RetType{VoidTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// void bcopy(const void *s1, void *s2, size_t n);
    // addToFunctionSummaryMap("bcopy",
    // Summary(ArgTypes{ConstVoidPtrTy,VoidPtrTy,SizeTy}, RetType{VoidTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(0), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// int bcmp(const void *s1, const void *s2, size_t n);
    // addToFunctionSummaryMap("bcmp",
    // Summary(ArgTypes{ConstVoidPtrTy,ConstVoidPtrTy,SizeTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// void bzero(void *s, size_t n);
    // addToFunctionSummaryMap("bzero",
    // Summary(ArgTypes{VoidPtrTy,SizeTy}, RetType{VoidTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
    //);

    //// int ftime(struct timeb *tp);
    // addToFunctionSummaryMap("ftime",
    // Summary(ArgTypes{StructTimebPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// wchar_t *wcswcs(const wchar_t *ws1, const wchar_t *ws2);
    // addToFunctionSummaryMap("wcswcs",
    // Summary(ArgTypes{ConstWchar_tPtrTy,ConstWchar_tPtrTy},
    // RetType{Wchar_tPtrTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// char *stpcpy(char *desstr, const char *srcstr);
    // addToFunctionSummaryMap("stpcpy",
    // Summary(ArgTypes{CharPtrTy,ConstCharPtrTy}, RetType{CharPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// char *index(const char *s, int c);
    // addToFunctionSummaryMap("index",
    // Summary(ArgTypes{ConstCharPtrTy,IntTy}, RetType{CharPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// char *rindex(const char *s, int c);
    // addToFunctionSummaryMap("rindex",
    // Summary(ArgTypes{ConstCharPtrTy,IntTy}, RetType{CharPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_cond_signal(pthread_cond_t *cond);
    // addToFunctionSummaryMap("pthread_cond_signal",
    // Summary(ArgTypes{Pthread_cond_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_cond_broadcast(pthread_cond_t *cond);
    // addToFunctionSummaryMap("pthread_cond_broadcast",
    // Summary(ArgTypes{Pthread_cond_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_create(pthread_t * thread, const pthread_attr_t * attr,
    /// void *(*start_routine)(void*), void * arg);
    // addToFunctionSummaryMap("pthread_create",
    // Summary(ArgTypes{Pthread_tPtrTy,ConstPthread_attr_tPtrTy,Void*(*)(void*)Ty,VoidPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(2)))
    //);

    //// int pthread_attr_destroy(pthread_attr_t *attr);
    // addToFunctionSummaryMap("pthread_attr_destroy",
    // Summary(ArgTypes{Pthread_attr_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_attr_init(pthread_attr_t *attr);
    // addToFunctionSummaryMap("pthread_attr_init",
    // Summary(ArgTypes{Pthread_attr_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_attr_setstackaddr(pthread_attr_t *attr, void *stackaddr);
    // addToFunctionSummaryMap("pthread_attr_setstackaddr",
    // Summary(ArgTypes{Pthread_attr_tPtrTy,VoidPtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int pthread_attr_getstackaddr(const pthread_attr_t *attr, void
    ///**stackaddr);
    // addToFunctionSummaryMap("pthread_attr_getstackaddr",
    // Summary(ArgTypes{ConstPthread_attr_tPtrTy,VoidPtrPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int pthread_attr_setstacksize(pthread_attr_t *attr, size_t
    /// stacksize);
    // addToFunctionSummaryMap("pthread_attr_setstacksize",
    // Summary(ArgTypes{Pthread_attr_tPtrTy,SizeTy}, RetType{IntTy},
    // NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
    //);

    //// int pthread_attr_setguardsize(pthread_attr_t *attr, size_t
    /// guardsize);
    // addToFunctionSummaryMap("pthread_attr_setguardsize",
    // Summary(ArgTypes{Pthread_attr_tPtrTy,SizeTy}, RetType{IntTy},
    // NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
    //);

    //// int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t
    ///*stacksize);
    // addToFunctionSummaryMap("pthread_attr_getstacksize",
    // Summary(ArgTypes{ConstPthread_attr_tPtrTy,SizePtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int pthread_attr_getguardsize(const pthread_attr_t *attr, size_t
    ///*guardsize);
    // addToFunctionSummaryMap("pthread_attr_getguardsize",
    // Summary(ArgTypes{ConstPthread_attr_tPtrTy,SizePtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int pthread_mutex_init(pthread_mutex_t *restrict mutex, const
    /// pthread_mutexattr_t *restrict attr);
    // addToFunctionSummaryMap("pthread_mutex_init",
    // Summary(ArgTypes{Pthread_mutex_tPtrRestrictTy,ConstPthread_mutexattr_tPtrRestrictTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_mutex_destroy(pthread_mutex_t *mutex);
    // addToFunctionSummaryMap("pthread_mutex_destroy",
    // Summary(ArgTypes{Pthread_mutex_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_mutex_lock(pthread_mutex_t *mutex);
    // addToFunctionSummaryMap("pthread_mutex_lock",
    // Summary(ArgTypes{Pthread_mutex_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_mutex_trylock(pthread_mutex_t *mutex);
    // addToFunctionSummaryMap("pthread_mutex_trylock",
    // Summary(ArgTypes{Pthread_mutex_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int pthread_mutex_unlock(pthread_mutex_t *mutex);
    // addToFunctionSummaryMap("pthread_mutex_unlock",
    // Summary(ArgTypes{Pthread_mutex_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// char *crypt(const char *key, const char *salt);
    // addToFunctionSummaryMap("crypt",
    // Summary(ArgTypes{ConstCharPtrTy,ConstCharPtrTy}, RetType{CharPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// char *ttyname(int fd);
    // addToFunctionSummaryMap("ttyname",
    // Summary(ArgTypes{IntTy}, RetType{CharPtrTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// int ttyname_r(int fd, char *buf, size_t buflen);
    // addToFunctionSummaryMap("ttyname_r",
    // Summary(ArgTypes{IntTy,CharPtrTy,SizeTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// struct spwd *getspnam(const char *name);
    // addToFunctionSummaryMap("getspnam",
    // Summary(ArgTypes{ConstCharPtrTy}, RetType{StructSpwdPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // FIXME Unix / Linux, or GNU only.
    //// struct spwd *fgetspent(FILE *fp);
    // addToFunctionSummaryMap("fgetspent",
    // Summary(ArgTypes{FilePtrTy}, RetType{StructSpwdPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // FIXME Unix / Linux, or GNU only.
    //// struct spwd *sgetspent(const char *s);
    // addToFunctionSummaryMap("sgetspent",
    // Summary(ArgTypes{ConstCharPtrTy}, RetType{StructSpwdPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // FIXME Conforming To SVr4.
    //// struct passwd *fgetpwent(FILE *stream);
    // addToFunctionSummaryMap("fgetpwent",
    // Summary(ArgTypes{FilePtrTy}, RetType{StructPasswdPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // FIXME GNU extension.
    // addToFunctionSummaryMap("getgrent_r",
    // Summary(ArgTypes{}, RetType{}, NoEvalCall)
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    // FIXME Conforming To SVr4.
    //// struct group *fgetgrent(FILE *stream);
    // addToFunctionSummaryMap("fgetgrent",
    // Summary(ArgTypes{FilePtrTy}, RetType{StructGroupPtrTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    // FIXME available in most Unix, but not POSIX.
    //// int getnetgrent(char **host, char **user, char **domain);
    // addToFunctionSummaryMap("getnetgrent",
    // Summary(ArgTypes{CharPtrPtrTy,CharPtrPtrTy,CharPtrPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(NotNull(ArgNo(2)))
    //);

    //// struct group *getgrnam(const char *name);
    // addToFunctionSummaryMap("getgrnam",
    // Summary(ArgTypes{ConstCharPtrTy}, RetType{StructGroupPtrTy},
    // NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// long telldir(DIR *dirp);
    // addToFunctionSummaryMap("telldir",
    // Summary(ArgTypes{DirPtrTy}, RetType{LongTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int scandir(const char *dir, struct dirent ***namelist,
    //       int (*sel)(const struct dirent *),
    //              int (*compar)(const struct dirent **, const struct dirent
    //              **));
    // addToFunctionSummaryMap("scandir",
    // Summary(ArgTypes{}, RetType{}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(NotNull(ArgNo(3)))
    //);

    //// size_t strnlen(const char *s, size_t maxlen);
    // addToFunctionSummaryMap("strnlen",
    // Summary(ArgTypes{ConstCharPtrTy,SizeTy}, RetType{SizeTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
    //);

    //// size_t wcsnlen(const wchar_t *s, size_t maxlen);
    // addToFunctionSummaryMap("wcsnlen",
    // Summary(ArgTypes{ConstWchar_tPtrTy,SizeTy}, RetType{SizeTy},
    // NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
    //);

    //// int shmget(key_t key, size_t size, int shmflg);
    // addToFunctionSummaryMap("shmget",
    // Summary(ArgTypes{Key_tTy,SizeTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(0, Max)))
    //);

    //// int getrlimit(int resource, struct rlimit *rlim);
    // addToFunctionSummaryMap("getrlimit",
    // Summary(ArgTypes{IntTy,StructRlimitPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int setrlimit(int resource, const struct rlimit *rlim);
    // addToFunctionSummaryMap("setrlimit",
    // Summary(ArgTypes{IntTy,ConstStructRlimitPtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int glob(const char *pattern, int flags, int (*errfunc) (const char
    ///*epath, int eerrno), glob_t *pglob);
    // addToFunctionSummaryMap("glob",
    // Summary(ArgTypes{ConstCharPtrTy,IntTy,Int(*)(constCharPtrTy,Int)Ty,Glob_tPtrTy},
    // RetType{IntTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(3)))
    //);

    //// void globfree(glob_t *pglob);
    // addToFunctionSummaryMap("globfree",
    // Summary(ArgTypes{}, RetType{}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// wchar_t *wcpncpy(wchar_t *dest, const wchar_t *src, size_t n);
    // addToFunctionSummaryMap("wcpncpy",
    // Summary(ArgTypes{Wchar_tPtrTy,ConstWchar_tPtrTy,SizeTy},
    // RetType{Wchar_tPtrTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(0), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// char *stpncpy(char *dest, const char *src, size_t n);
    // addToFunctionSummaryMap("stpncpy",
    // Summary(ArgTypes{CharPtrTy,ConstCharPtrTy,SizeTy}, RetType{CharPtrTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(0), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// void *memccpy(void *dest, const void *src, int c, size_t n);
    // addToFunctionSummaryMap("memccpy",
    // Summary(ArgTypes{VoidPtrTy,ConstVoidPtrTy,IntTy,SizeTy},
    // RetType{VoidPtrTy}, NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //.ArgConstraint(ArgumentCondition(3, WithinRange, Range(0, Max)))
    //);

    //// int getitimer(int which, struct itimerval *curr_value);
    // addToFunctionSummaryMap("getitimer",
    // Summary(ArgTypes{IntTy,StructItimervalPtrTy}, RetType{IntTy},
    // NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int sigsuspend(const sigset_t *mask);
    // addToFunctionSummaryMap("sigsuspend",
    // Summary(ArgTypes{ConstSigset_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int getrusage(int who, struct rusage *usage);
    // addToFunctionSummaryMap("getrusage",
    // Summary(ArgTypes{IntTy,StructRusagePtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int sigemptyset(sigset_t *set);
    // addToFunctionSummaryMap("sigemptyset",
    // Summary(ArgTypes{Sigset_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int sigfillset(sigset_t *set);
    // addToFunctionSummaryMap("sigfillset",
    // Summary(ArgTypes{Sigset_tPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int sigaddset(sigset_t *set, int signum);
    // addToFunctionSummaryMap("sigaddset",
    // Summary(ArgTypes{Sigset_tPtrTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int sigdelset(sigset_t *set, int signum);
    // addToFunctionSummaryMap("sigdelset",
    // Summary(ArgTypes{Sigset_tPtrTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int sigismember(const sigset_t *set, int signum);
    // addToFunctionSummaryMap("sigismember",
    // Summary(ArgTypes{ConstSigset_tPtrTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
    //       int msgflg);
    // addToFunctionSummaryMap("msgrcv",
    // Summary(ArgTypes{}, RetType{}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
    // addToFunctionSummaryMap("msgsnd",
    // Summary(ArgTypes{IntTy,ConstVoidPtrTy,SizeTy,IntTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// int tcflow(int fildes, int action);
    // addToFunctionSummaryMap("tcflow",
    // Summary(ArgTypes{IntTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// int tcflush(int fildes, int queue_selector);
    // addToFunctionSummaryMap("tcflush",
    // Summary(ArgTypes{IntTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// int tcsendbreak(int fildes, int duration);
    // addToFunctionSummaryMap("tcsendbreak",
    // Summary(ArgTypes{IntTy,IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// int tcgetattr(int fildes, struct termios *termios_p);
    // addToFunctionSummaryMap("tcgetattr",
    // Summary(ArgTypes{IntTy,StructTermiosPtrTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //.ArgConstraint(NotNull(ArgNo(1)))
    //);

    //// int tcsetattr(int fildes, int optional_actions, const struct termios
    ///*termios_p);
    // addToFunctionSummaryMap("tcsetattr",
    // Summary(ArgTypes{IntTy,IntTy,ConstStructTermiosPtrTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(ArgumentCondition(0, WithinRange, Range(0,
    // Max))) .ArgConstraint(NotNull(ArgNo(2)))
    //);

    //// int cfsetospeed(struct termios *termios_p, speed_t speed);
    // addToFunctionSummaryMap("cfsetospeed",
    // Summary(ArgTypes{StructTermiosPtrTy,Speed_tTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int cfsetispeed(struct termios *termios_p, speed_t speed);
    // addToFunctionSummaryMap("cfsetispeed",
    // Summary(ArgTypes{StructTermiosPtrTy,Speed_tTy}, RetType{IntTy},
    // NoEvalCall) .ArgConstraint(NotNull(ArgNo(0)))
    //);

    //// int tcdrain(int fildes);
    // addToFunctionSummaryMap("tcdrain",
    // Summary(ArgTypes{IntTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);

    //// void swab(const void * src, void* dest, ssize_t bytes);
    // addToFunctionSummaryMap("swab",
    // Summary(ArgTypes{ConstVoidPtrTy,VoidPtrTy,Ssize_tTy}, RetType{VoidTy},
    // NoEvalCall) .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(0),
    ///*BufSize=*/ArgNo(2))) .ArgConstraint(NotNull(ArgNo(1)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(1), /*BufSize=*/ArgNo(2)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// int gethostname(char *name, size_t len);
    // addToFunctionSummaryMap("gethostname",
    // Summary(ArgTypes{CharPtrTy,SizeTy}, RetType{IntTy}, NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(BufferSize(/*Buffer=*/ArgNo(0), /*BufSize=*/ArgNo(1)))
    //.ArgConstraint(ArgumentCondition(1, WithinRange, Range(1, Max)))
    //);

    //// int posix_memalign(void **memptr, size_t alignment, size_t size);
    // addToFunctionSummaryMap("posix_memalign",
    // Summary(ArgTypes{VoidPtrPtrTy,SizeTy,SizeTy}, RetType{IntTy},
    // NoEvalCall)
    //.ArgConstraint(NotNull(ArgNo(0)))
    //.ArgConstraint(ArgumentCondition(2, WithinRange, Range(0, Max)))
    //);

    //// void *valloc(size_t size);
    // addToFunctionSummaryMap("valloc",
    // Summary(ArgTypes{SizeTy}, RetType{VoidPtrTy}, NoEvalCall)
    //.ArgConstraint(ArgumentCondition(0, WithinRange, Range(0, Max)))
    //);
  }

  // Functions for testing.
  if (ChecksEnabled[CK_StdCLibraryFunctionsTesterChecker]) {
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
        "__buf_size_arg_constraint",
        Summary(ArgTypes{ConstVoidPtrTy, SizeTy}, RetType{IntTy},
                EvalCallAsPure)
            .ArgConstraint(
                BufferSize(/*Buffer=*/ArgNo(0), /*BufSize=*/ArgNo(1))));
    addToFunctionSummaryMap(
        "__buf_size_arg_constraint_mul",
        Summary(ArgTypes{ConstVoidPtrTy, SizeTy, SizeTy}, RetType{IntTy},
                EvalCallAsPure)
            .ArgConstraint(BufferSize(/*Buffer=*/ArgNo(0), /*BufSize=*/ArgNo(1),
                                      /*BufSizeMultiplier=*/ArgNo(2))));
  }
}

void ento::registerStdCLibraryFunctionsChecker(CheckerManager &mgr) {
  auto *Checker = mgr.registerChecker<StdLibraryFunctionsChecker>();
  Checker->DisplayLoadedSummaries =
      mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "DisplayLoadedSummaries");
  Checker->ModelPOSIX =
      mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "ModelPOSIX");
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
