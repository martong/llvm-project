/*
** -----------------------------------------------------------------------------
** Copyright (c) Ericsson AB, 2020
** -----------------------------------------------------------------------------
**
** The copyright to the document(s) herein is the property of
**
** Ericsson AB, Sweden.
**
** The document(s) may be used, copied or otherwise distributed only with
** the written permission from Ericsson AB or in accordance with the
** terms and conditions stipulated in the agreement/contract under which
** the document(s) have been supplied.
**
** -----------------------------------------------------------------------------
*/

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "clang/AST/CharUnits.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/APSIntType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include <cmath> //Needed for floor and log functions.

using namespace clang;
using namespace ento;

// Needed to simplify the right hand side, if it is a complex expression.
static std::pair<NonLoc, nonloc::ConcreteInt>
getSimplifiedExpression(NonLoc shiftBy, nonloc::ConcreteInt typeLength,
                        SValBuilder &svalBuilder) {
  Optional<nonloc::SymbolVal> SymVal = shiftBy.getAs<nonloc::SymbolVal>();
  if (SymVal && SymVal->isExpression()) {
    if (const SymIntExpr *SIE = dyn_cast<SymIntExpr>(SymVal->getSymbol())) {
      llvm::APSInt constant =
          APSIntType(typeLength.getValue()).convert(SIE->getRHS());
      switch (SIE->getOpcode()) {
      case BO_Mul:

        if ((typeLength.getValue() % constant) != 0)
          return std::pair<NonLoc, nonloc::ConcreteInt>(shiftBy, typeLength);
        else
          return getSimplifiedExpression(
              nonloc::SymbolVal(SIE->getLHS()),
              svalBuilder.makeIntVal(typeLength.getValue() / constant),
              svalBuilder);
      case BO_Add:
        return getSimplifiedExpression(
            nonloc::SymbolVal(SIE->getLHS()),
            svalBuilder.makeIntVal(typeLength.getValue() - constant),
            svalBuilder);
      default:
        break;
      }
    }
  }

  return std::pair<NonLoc, nonloc::ConcreteInt>(shiftBy, typeLength);
}

class BitwiseShiftChecker : public Checker<check::PreStmt<BinaryOperator>> {

private:
  enum ShiftType { LeftShift, RightShift };
  std::unique_ptr<BugType> CustomBugType;

public:
  BitwiseShiftChecker() {
    CustomBugType.reset(
        new BugType(this, "Bitwise shift", "Suspicious operation"));
  }

  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const {
    BinaryOperator::Opcode Op = B->getOpcode();
    if (Op != BO_Shl && Op != BO_Shr)
      return;

    if (Op == BO_Shl)
      LeftShiftChecks(B, C);
    else if (Op == BO_Shr)
      RightShiftChecks(B, C);
  }

  void LeftShiftChecks(const BinaryOperator *B, CheckerContext &C) const {
    if (GeneralOverShiftCheck(B, C, LeftShift))
      return;

    if (OperandNegativityCheck(B, C, LeftShift))
      return;

    if (LeftShiftBitOverflowCheck(B, C))
      return;
  }

  void RightShiftChecks(const BinaryOperator *B, CheckerContext &C) const {
    if (GeneralOverShiftCheck(B, C, RightShift))
      return;

    if (OperandNegativityCheck(B, C, RightShift))
      return;
  }

  bool GeneralOverShiftCheck(const BinaryOperator *B, CheckerContext &C,
                             ShiftType type) const {
    // We need the type length of the left hand side element. ( That we wish to
    // shift. )
    QualType LHSType = B->getLHS()->getType();
    if (LHSType.isNull())
      return false;

    unsigned long long LeftTypeLength = C.getASTContext().getIntWidth(LHSType);

    // We generate a defined Sval with the type length.
    DefinedSVal DefinedLeftTypeLength = C.getSValBuilder().makeIntVal(
        LeftTypeLength, C.getASTContext().LongLongTy);

    // We need the state and the SvalBuilder.
    ProgramStateRef State = C.getState();
    SValBuilder &Bldr = C.getSValBuilder();

    // We ask for the right hand side. ( The value we wish to shift with. )
    SVal Right = C.getSVal(B->getRHS());

    // FIXME: For SIMD vector types (using
    // `__attribute__(ext_vector_type(<NUMBER>)`) on the left-hand side Clang
    // also inserts implicit cast to the right-hand side. This seems to be
    // incorrect according to the standard. Worse, that in these cases the
    // concrete integer on the right-hand side becomes `Unknown`.
    if (Right.isUnknown())
      return false;

    // We need to simplify the right and side if it is an expression.
    std::pair<NonLoc, nonloc::ConcreteInt> simpleExpression =
        getSimplifiedExpression(
            Right.castAs<NonLoc>(),
            DefinedLeftTypeLength.castAs<nonloc::ConcreteInt>(), Bldr);

    // Evaluate the binary operation
    SVal Eval = Bldr.evalBinOpNN(State, BO_GE, simpleExpression.first,
                                 simpleExpression.second.castAs<NonLoc>(),
                                 Bldr.getConditionType());

    // Make a defined or unknown sval that is needed for assume.
    Optional<NonLoc> expressionToCheck = Eval.getAs<NonLoc>();
    if (!expressionToCheck)
      return false;

    ProgramStateRef StTrue, StFalse;
    std::tie(StTrue, StFalse) = State->assume(*expressionToCheck);

    if (StTrue && !StFalse) {
      if (type == LeftShift)
        reportBug("Left shift right operand is greater than left type capacity",
                  State, C);
      else if (type == RightShift)
        reportBug(
            "Right shift right operand is greater than left type capacity",
            State, C);

      return true;
    } else
      return false;
  }

  bool CheckNegativity(CheckerContext &C, const DefinedSVal &Zero,
                       const SVal &Operand) const {
    SValBuilder &Bldr = C.getSValBuilder();

    // FIXME: For SIMD vector types (using
    // `__attribute__(ext_vector_type(<NUMBER>)`) on the left-hand side Clang
    // also inserts implicit cast to the right-hand side. This seems to be
    // incorrect according to the standard. Worse, that in these cases the
    // concrete integer on the right-hand side becomes `Unknown`.
    if (Operand.isUnknown())
      return false;

    // If operand is an expression, it needs to be simplified.
    std::pair<NonLoc, nonloc::ConcreteInt> simpleExpression =
        getSimplifiedExpression(Operand.castAs<NonLoc>(),
                                Zero.castAs<nonloc::ConcreteInt>(), Bldr);

    ProgramStateRef State = C.getState();
    SVal Eval = Bldr.evalBinOp(State, BO_LT, simpleExpression.first,
                               simpleExpression.second.castAs<NonLoc>(),
                               Bldr.getConditionType());
    if (!Eval.isValid())
      return false;

    ConstraintManager &CM = C.getConstraintManager();
    ProgramStateRef StTrue, StFalse;
    std::tie(StTrue, StFalse) =
        CM.assumeDual(State, Eval.castAs<DefinedSVal>());
    return StTrue && !StFalse;
  }

  // From 5.8 [expr.shift] (N4296, 2014-11-19)
  // 1. "... The behaviour is undefined if the right operand is negative..."
  // 2. "The value of E1 << E2 ...
  //     if E1 has a signed type and non-negative value ...
  //     otherwise, the behavior is undefined."
  // 3. "The value of E1 >> E2 ...
  //     If E1 has a signed type and a negative value,
  //     the resulting value is implementation-defined."
  // In conclusion: neither of left and right operands should be negative.
  bool OperandNegativityCheck(const BinaryOperator *B, CheckerContext &C,
                              ShiftType type) const {
    // Create Zero value to compare against.
    DefinedSVal Zero =
        C.getSValBuilder().makeIntVal(0, C.getASTContext().LongLongTy);

    // Check if any of the operands is negative.
    bool IsLeftNegative = (!B->getLHS()->getType()->isUnsignedIntegerType() &&
                           CheckNegativity(C, Zero, C.getSVal(B->getLHS())));
    bool IsRightNegative = (!B->getRHS()->getType()->isUnsignedIntegerType() &&
                            CheckNegativity(C, Zero, C.getSVal(B->getRHS())));

    // Evaluate the results and report the bugs based on the negative values.
    if (IsLeftNegative) {
      if (type == LeftShift)
        reportBug("Left operand is negative in left shift", C.getState(), C);
      else if (type == RightShift)
        reportBug("Left operand is negative in right shift", C.getState(), C);
    }

    if (IsRightNegative) {
      if (type == LeftShift)
        reportBug("Right operand is negative in left shift", C.getState(), C);
      else if (type == RightShift)
        reportBug("Right operand is negative in right shift", C.getState(), C);
    }

    return IsLeftNegative || IsRightNegative;
  }

  bool LeftShiftBitOverflowCheck(const BinaryOperator *B,
                                 CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    SValBuilder &Bldr = C.getSValBuilder();

    // We need to check if left hand side operand is signed and positive.
    // If unsigned  then we should return.
    // If unsigned or negative then we should report an error.

    if (B->getLHS()->getType()->isUnsignedIntegerType())
      return false; // Return with false we don't need to report an error, this
                    // is well defined.

    // As of now, this check only works if the left operand is a concrete
    // integral.

    SVal Left = C.getSVal(B->getLHS());
    Optional<nonloc::ConcreteInt> leftValueCheck =
        Left.getAs<nonloc::ConcreteInt>();
    if (llvm::None != leftValueCheck) {
      // llvm::APSInt leftValue = Left.castAs<nonloc::ConcreteInt>().getValue();

      // Get the type length of left type
      unsigned long long leftTypeSize =
          C.getASTContext().getIntWidth(B->getLHS()->getType());

      // Get the value of the left hand side.
      // Left can't be negative, that has been checked
      // before.(LeftOperandNegativityCheck)
      unsigned long long neededBits =
          Left.castAs<nonloc::ConcreteInt>().getValue().getActiveBits();

      // Calculate by how much we can shift that is still well defined.
      unsigned long long allowedShift = leftTypeSize - neededBits;

      DefinedSVal Allowed = C.getSValBuilder().makeIntVal(
          allowedShift, C.getASTContext().LongLongTy);

      SVal Right = C.getSVal(B->getRHS());

      /*
      Addendum needed because C++ and C standard difference.
      In C++ shift is well defined here if new number is
      representable in the corresponding unsigned type.
      The C standard is stricter here, it has to be
      representable in the correspondig signed type.
      */
      BinaryOperator::Opcode opcode;
      if (!C.getLangOpts().CPlusPlus)
        opcode = BO_GE;
      else
        opcode = BO_GT;

      SVal Eval = Bldr.evalBinOpNN(State, opcode, Right.castAs<NonLoc>(),
                                   Allowed.castAs<nonloc::ConcreteInt>(),
                                   Bldr.getConditionType());
      if (!Eval.isValid())
        return false;

      ConstraintManager &CM = C.getConstraintManager();
      ProgramStateRef StTrue, StFalse;
      std::tie(StTrue, StFalse) =
          CM.assumeDual(State, Eval.castAs<DefinedSVal>());

      if (StTrue && !StFalse) {
        reportBug("Bit overflow in left shift", State, C);
        return true;
      } else
        return false;
    }
    return false;
  }

  void reportBug(const char *Msg, const ProgramStateRef &State,
                 CheckerContext &C) const {
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode(State);
    auto R =
        std::make_unique<PathSensitiveBugReport>(*CustomBugType, Msg, ErrNode);
    C.emitReport(std::move(R));
  }
};
// BitwiseShiftChecker class

void ento::registerBitwiseShiftChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<BitwiseShiftChecker>();
}

bool ento::shouldRegisterBitwiseShiftChecker(const CheckerManager &mgr) {
  return true;
}
