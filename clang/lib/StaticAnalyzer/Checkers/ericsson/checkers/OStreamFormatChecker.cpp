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


//===-- OStreamFormatChecker.cpp ------------------------------*- C++ -*--//
//
// This file defines an ostream format state checker, that checks for possibly
// forgotten format state modifications.
// We identify the ostream objects by memory region, and check for "same scope"
// modifications. That means the checker should warn if we have modified the
// stream object's format, and forgotten to restore it before the end of the
// function in which the modification occured.
// Since istream behaves very similarly, this checker could easily be extended
// to provide istream support as well.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
// Wrapper for each individual state category that
// the checker tracks.
// The first template argument should be a primitive type,
// the second is the default value that the checker considers
// "normal" format.
// See Standard: N4606 27.5.5.2 basic_ios constructors.
template <class StorageType, StorageType Default> class State {
public:
  static_assert(std::is_integral<StorageType>::value ||
                    std::is_enum<StorageType>::value,
                "Only integral types or enums are supported.");
  State() : State(Default) {}
  explicit State(const StorageType &StateValue) : StateValue(StateValue) {}
  bool operator==(const State &rhs) const {
    return StateValue == rhs.StateValue;
  }
  StorageType getState() const { return StateValue; }
  bool isDefault() const { return StateValue == Default; }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(static_cast<int>(StateValue));
  }

private:
  StorageType StateValue;
};

enum class NumericFormat { DEC = 0, OCT, HEX };
typedef State<NumericFormat, NumericFormat::DEC> NumericFormatState;

const unsigned DEFAULT_PRECISION = 6;

typedef State<unsigned int, DEFAULT_PRECISION> NumericPrecisionState;

enum class Justification { RIGHT = 0, LEFT, INTERNAL };
typedef State<Justification, Justification::RIGHT> JustificationState;

typedef State<bool, false> BoolAlphaState;

typedef State<bool, false> ShowPosState;

typedef State<bool, false> ShowBaseState;

typedef State<bool, false> UpperCaseState;

typedef State<bool, false> ShowPointState;

enum class FloatingPoint { NOT_SET = 0, FIXED, SCIENTIFIC };
typedef State<FloatingPoint, FloatingPoint::NOT_SET> FloatingPointState;

typedef State<bool, false> FlagsCalledState;

// This aggregate state stores the basic states that we track, and
// also the scope, in which the first modification occured.
class StoredState {
public:
  explicit StoredState(const FunctionDecl *Scope) : Scope(Scope) {}

  bool operator==(const StoredState &OtherState) const {
    return Format == OtherState.Format && Precision == OtherState.Precision &&
           Justification == OtherState.Justification &&
           BoolAlpha == OtherState.BoolAlpha && ShowPos == OtherState.ShowPos &&
           ShowBase == OtherState.ShowBase &&
           UpperCase == OtherState.UpperCase &&
           ShowPoint == OtherState.ShowPoint &&
           FloatingPoint == OtherState.FloatingPoint &&
           FlagsCalled == OtherState.FlagsCalled;
  }

  // A stream is considered default if every state is default, except
  // FlagsCalled which behaves like an inverted state.
  // We consider a stream default if there
  // was a flag call on it. If someone calls flags() to copy the format flags
  // we consider the stream saved, and dont report it.
  // Consider following example:
  //
  // void safePrintFunction(int valueToPrint) {
  //   StreamState SS(std::cout);
  //   std::cout <<
  //     "According to my calculations the hexadecimal value is " <<
  //     std::hex <<
  //     valueToPring <<
  //     std::endl;
  // }
  //
  // If SS is an object that calls flags() on its constructor argument,
  // and in its destructor restores it in the original stream,
  // then it effectively saves the formatting state of that stream.
  // Example of such class:
  //
  // class StreamState {
  // public:
  //   StreamState(std::ostream& out)
  //      : m_out(out), m_fmt(out.flags()), m_prec(out.precision()) {}
  //
  //   ~StreamState() {
  //      m_out.precision(m_prec);
  //      m_out.flags(m_fmt);
  //   }
  //
  // private:
  //   std::ostream& m_out;
  //   std::ios_base::fmtflags m_fmt;
  //   std::streamsize m_prec;
  // };
  //
  // FIXME: A more elaborate solution could be added to support this
  // stream saving logic.
  bool isDefault() const {
    return (Format.isDefault() && Precision.isDefault() &&
            Justification.isDefault() && BoolAlpha.isDefault() &&
            ShowPos.isDefault() && ShowBase.isDefault() &&
            UpperCase.isDefault() && ShowPoint.isDefault() &&
            FloatingPoint.isDefault()) ||
           !FlagsCalled.isDefault();
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Scope);
    Format.Profile(ID);
    Precision.Profile(ID);
    Justification.Profile(ID);
    BoolAlpha.Profile(ID);
    ShowPos.Profile(ID);
    ShowBase.Profile(ID);
    UpperCase.Profile(ID);
    ShowPoint.Profile(ID);
    FloatingPoint.Profile(ID);
    FlagsCalled.Profile(ID);
  }

  const FunctionDecl *getScope() const { return Scope; }

  // All apply functions behave like ProgramState, so when we modify
  // a StoredState object we return a copy of the original. This
  // ensures that we dont have accidentally have access to references of
  // States from another ProgramState.

  StoredState applyNumericState(const NumericFormat &format) const {
    StoredState Copy(*this);
    Copy.Format = NumericFormatState(format);
    return Copy;
  }

  StoredState applyPrecisionState(unsigned int precision) const {
    StoredState Copy(*this);
    Copy.Precision = NumericPrecisionState(precision);
    return Copy;
  }

  StoredState
  applyJustificationState(const enum Justification &justification) const {
    StoredState Copy(*this);
    Copy.Justification = JustificationState(justification);
    return Copy;
  }

  StoredState applyBoolAlphaState(bool boolAlpha) const {
    StoredState Copy(*this);
    Copy.BoolAlpha = BoolAlphaState(boolAlpha);
    return Copy;
  }

  StoredState applyShowPosState(bool showPos) const {
    StoredState Copy(*this);
    Copy.ShowPos = ShowPosState(showPos);
    return Copy;
  }

  StoredState applyShowBaseState(bool showBase) const {
    StoredState Copy(*this);
    Copy.ShowBase = ShowBaseState(showBase);
    return Copy;
  }

  StoredState applyUpperCaseState(bool upperCase) const {
    StoredState Copy(*this);
    Copy.UpperCase = UpperCaseState(upperCase);
    return Copy;
  }

  StoredState applyShowPointState(bool showPoint) const {
    StoredState Copy(*this);
    Copy.ShowPoint = ShowPointState(showPoint);
    return Copy;
  }

  StoredState
  applyFloatingPointState(const enum FloatingPoint &floatingPoint) const {
    StoredState Copy(*this);
    Copy.FloatingPoint = FloatingPointState(floatingPoint);
    return Copy;
  }

  StoredState applyFlagsCalledState(bool flagsCalled) const {
    StoredState Copy(*this);
    Copy.FlagsCalled = FlagsCalledState(flagsCalled);
    return Copy;
  }

private:
  // We identify the scope of modification by the fully quailfied
  // name of the enclosing function.
  // Note that this does not account for example local
  // block expressions, so at the end of our tracked scope the
  // ostream variable could already be destroyed.
  const FunctionDecl *Scope;

  NumericFormatState Format;
  NumericPrecisionState Precision;
  JustificationState Justification;
  BoolAlphaState BoolAlpha;
  ShowPosState ShowPos;
  ShowBaseState ShowBase;
  UpperCaseState UpperCase;
  ShowPointState ShowPoint;
  FloatingPointState FloatingPoint;
  FlagsCalledState FlagsCalled;
};

// Most of the time only a small number of stream objects are
// handled in a scope.
typedef SmallVector<std::pair<const MemRegion *, StoredState>, 4>
    SmallFormatVec;

// The checker uses checkPreCall check to populate the
// state map with modifications, and to keep track of
// changes. The endFunction check is used to examine
// the tracked states, and emit warnings if needed.
class OStreamFormatChecker
    : public Checker<eval::Call, check::PreCall, check::EndFunction> {
private:
  mutable std::unique_ptr<BugType> OStreamFormatBugType;
  mutable IdentifierInfo *II_BasicOstream, *II_Flags, *II_Setf, *II_Unsetf,
      *II_Setiosflags, *II_Resetiosflags, *II_Precision, *II_SetPrecision,
      *II_BaseField, *II_Hex, *II_Dec, *II_Oct, *II_AdjustField, *II_Left,
      *II_Right, *II_Internal, *II_BoolAlpha, *II_NoBoolAlpha, *II_ShowPos,
      *II_NoShowPos, *II_ShowBase, *II_NoShowBase, *II_UpperCase,
      *II_NoUpperCase, *II_ShowPoint, *II_NoShowPoint, *II_FloatField,
      *II_Fixed, *II_Scientific;

public:
  OStreamFormatChecker()
      : II_BasicOstream(nullptr), II_Flags(nullptr), II_Setf(nullptr),
        II_Unsetf(nullptr), II_Setiosflags(nullptr), II_Resetiosflags(nullptr),
        II_Precision(nullptr), II_SetPrecision(nullptr), II_BaseField(nullptr),
        II_Hex(nullptr), II_Dec(nullptr), II_Oct(nullptr),
        II_AdjustField(nullptr), II_Left(nullptr), II_Right(nullptr),
        II_Internal(nullptr), II_BoolAlpha(nullptr), II_NoBoolAlpha(nullptr),
        II_ShowPos(nullptr), II_NoShowPos(nullptr), II_ShowBase(nullptr),
        II_NoShowBase(nullptr), II_UpperCase(nullptr), II_NoUpperCase(nullptr),
        II_ShowPoint(nullptr), II_NoShowPoint(nullptr), II_FloatField(nullptr),
        II_Fixed(nullptr), II_Scientific(nullptr) {}

  void initIdents(const ASTContext &AC) const;

  void reportFormatWarning(const SmallFormatVec &Streams,
                           const ExplodedNode *ErrNode,
                           CheckerContext &C) const;

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &CE, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *, CheckerContext &C) const;

  ProgramStateRef checkForManipulator(const CXXOperatorCallExpr *OC,
                                      ProgramStateRef S,
                                      CheckerContext &C) const;
  ProgramStateRef checkForSimpleManip(const CXXOperatorCallExpr *LeftShift,
                                      ProgramStateRef S,
                                      CheckerContext &C) const;
  ProgramStateRef checkForComplexManip(const CXXOperatorCallExpr *LeftShift,
                                       ProgramStateRef S,
                                       CheckerContext &C) const;

  ProgramStateRef checkForMemberCall(const CXXMemberCall *MC, ProgramStateRef S,
                                     CheckerContext &C) const;

  ProgramStateRef handleMethodFlags(const CXXMemberCall *MC,
                                    const MemRegion *BMR, ProgramStateRef S,
                                    CheckerContext &C) const;
  ProgramStateRef handleMethodSetf(const CXXMemberCall *MC,
                                   const MemRegion *BMR, ProgramStateRef S,
                                   CheckerContext &C) const;
  ProgramStateRef handleMethodUnsetf(const CXXMemberCall *MC,
                                     const MemRegion *BMR, ProgramStateRef S,
                                     CheckerContext &C) const;
  ProgramStateRef handleMethodPrecision(const CXXMemberCall *MC,
                                        const MemRegion *BMR, ProgramStateRef S,
                                        CheckerContext &C) const;

  ProgramStateRef handleSimpleManip(const CXXOperatorCallExpr *OCE,
                                    const FunctionDecl *FD, ProgramStateRef S,
                                    CheckerContext &C) const;

  ProgramStateRef handleSetiosflags(const CXXOperatorCallExpr *OCE,
                                    const CallExpr *CE, ProgramStateRef S,
                                    CheckerContext &C) const;
  ProgramStateRef handleResetiosflags(const CXXOperatorCallExpr *OCE,
                                      const CallExpr *CE, ProgramStateRef S,
                                      CheckerContext &C) const;
  ProgramStateRef handleSetprecision(const CXXOperatorCallExpr *OCE,
                                     const CallExpr *CE, ProgramStateRef S,
                                     CheckerContext &C) const;

  StoredState applyStateFlagForSetting(const StoredState &OldState,
                                       const IdentifierInfo *Modifier) const;

  StoredState applyStateFlagForUnsetting(const StoredState &OldState,
                                         const IdentifierInfo *Modifier) const;
};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(OstreamStateMap, const MemRegion *, StoredState)

// Helper functions.

static const FunctionDecl *getContextAsFunc(CheckerContext &C) {
  return C.getLocationContext()->getDecl()->getAsFunction();
}

static const MemRegion *getMemRegionForExpr(const Expr *E, CheckerContext &C) {
  ProgramStateRef S = C.getState();
  const LocationContext *LC = C.getLocationContext();
  return S->getSVal(E, LC).getAsRegion();
}

// This function is meant to be used on a leftshift operator call.
static const MemRegion *
getMemRegionForFirstManipArg(const CXXOperatorCallExpr *OCE,
                             CheckerContext &C) {
  return getMemRegionForExpr(OCE->getArg(0), C);
}

static const IdentifierInfo *
getIdentifierInfoForMethodArg(const CXXMemberCall *MC, unsigned int ArgIndex,
                              CheckerContext &C) {
  // The argument must exist.
  if (MC->getNumArgs() <= ArgIndex)
    return nullptr;

  const auto *Arg =
      dyn_cast<DeclRefExpr>(MC->getArgExpr(ArgIndex)->IgnoreCasts());
  if (!Arg)
    return nullptr;

  // The argument must have a Decl.
  const NamedDecl *ArgDecl = Arg->getFoundDecl();
  if (!ArgDecl)
    return nullptr;

  // The argument must also be identifiable.
  const IdentifierInfo *ArgII = ArgDecl->getIdentifier();

  return ArgII;
}

static Optional<int> tryEvaluateAsInt(const Expr *E, ProgramStateRef S,
                                      CheckerContext C) {
  const llvm::APSInt *Result =
      C.getSValBuilder().getKnownValue(S, C.getSVal(E));
  if (Result)
    return Result->getExtValue();

  return None;
}

// Checker methods.

void OStreamFormatChecker::initIdents(const ASTContext &AC) const {
  if (!II_BasicOstream)
    II_BasicOstream = &AC.Idents.get("basic_ostream");

  if (!II_Flags)
    II_Flags = &AC.Idents.get("flags");

  if (!II_Setf)
    II_Setf = &AC.Idents.get("setf");

  if (!II_Unsetf)
    II_Unsetf = &AC.Idents.get("unsetf");

  if (!II_Setiosflags)
    II_Setiosflags = &AC.Idents.get("setiosflags");

  if (!II_Resetiosflags)
    II_Resetiosflags = &AC.Idents.get("resetiosflags");

  if (!II_Precision)
    II_Precision = &AC.Idents.get("precision");

  if (!II_SetPrecision)
    II_SetPrecision = &AC.Idents.get("setprecision");

  if (!II_BaseField)
    II_BaseField = &AC.Idents.get("basefield");

  if (!II_Hex)
    II_Hex = &AC.Idents.get("hex");

  if (!II_Dec)
    II_Dec = &AC.Idents.get("dec");

  if (!II_Oct)
    II_Oct = &AC.Idents.get("oct");

  if (!II_AdjustField)
    II_AdjustField = &AC.Idents.get("adjustField");

  if (!II_Left)
    II_Left = &AC.Idents.get("left");

  if (!II_Right)
    II_Right = &AC.Idents.get("right");

  if (!II_Internal)
    II_Internal = &AC.Idents.get("internal");

  if (!II_BoolAlpha)
    II_BoolAlpha = &AC.Idents.get("boolalpha");

  if (!II_NoBoolAlpha)
    II_NoBoolAlpha = &AC.Idents.get("noboolalpha");

  if (!II_ShowPos)
    II_ShowPos = &AC.Idents.get("showPos");

  if (!II_NoShowPos)
    II_NoShowPos = &AC.Idents.get("noshowpos");

  if (!II_ShowBase)
    II_ShowBase = &AC.Idents.get("showbase");

  if (!II_NoShowBase)
    II_NoShowBase = &AC.Idents.get("noshowbase");

  if (!II_UpperCase)
    II_UpperCase = &AC.Idents.get("uppercase");

  if (!II_NoUpperCase)
    II_NoUpperCase = &AC.Idents.get("nouppercase");

  if (!II_ShowPoint)
    II_ShowPoint = &AC.Idents.get("showpoint");

  if (!II_NoShowPoint)
    II_NoShowPoint = &AC.Idents.get("noshowpoint");

  if (!II_FloatField)
    II_FloatField = &AC.Idents.get("floatfield");

  if (!II_Scientific)
    II_Scientific = &AC.Idents.get("scientific");

  if (!II_Fixed)
    II_Fixed = &AC.Idents.get("fixed");
}

void OStreamFormatChecker::reportFormatWarning(const SmallFormatVec &Streams,
                                               const ExplodedNode *warnNode,
                                               CheckerContext &C) const {
  if (!OStreamFormatBugType)
    OStreamFormatBugType.reset(new BugType(
        this, "Possibly forgotten ostream format modification in scope",
        "OStream Format Warning"));
  for (auto &Stream : Streams) {
    auto R = std::make_unique<PathSensitiveBugReport>(
        *OStreamFormatBugType,
        "Possibly forgotten ostream format modification in scope", warnNode);
    R->markInteresting(Stream.first);
    C.emitReport(std::move(R));
  }
}

bool OStreamFormatChecker::evalCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const auto *CE = dyn_cast_or_null<CallExpr>(Call.getOriginExpr());
  if (!CE)
    return false;

  if (CE->getNumArgs() < 1)
    return false;

  const IdentifierInfo *Arg0II =
      CE->getArg(0)->getType().getBaseTypeIdentifier();
  if (Arg0II != II_BasicOstream)
    return false;

  const auto *OCE = dyn_cast<CXXOperatorCallExpr>(CE);
  if (!OCE)
    return false;

  if (OCE->getOperator() != OO_LessLess)
    return false;

  ProgramStateRef CurrentState = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  const SVal InStream =
      CurrentState->getSVal(CE->getArg(0), C.getLocationContext());
  // The return value of this call is a reference to the stream object itself.
  CurrentState = CurrentState->BindExpr(CE, LCtx, InStream);

  ProgramStateManager &PSM = C.getStateManager();
  CallEventManager &CEM = PSM.getCallEventManager();

  const CallEventRef<> CEvt = CEM.getSimpleCall(CE, CurrentState, LCtx);
  // Get the SVal of the stream object, which is the first argument.
  const SVal StreamSV = CEvt->getArgSVal(0);

  // Add the SVal of the StreamObject.
  SmallVector<SVal, 1> ValuesToInvalidate{StreamSV};
  RegionAndSymbolInvalidationTraits ETraits;

  const int BlockCount = C.blockCount();

  // The call possibly modifies the inner structure of the stream object.
  const ProgramStateRef RegionsInvalidated =
      CurrentState->invalidateRegions(ValuesToInvalidate, CE, BlockCount, LCtx,
                                      false, nullptr, CEvt.get(), &ETraits);

  C.addTransition(RegionsInvalidated);

  return true;
}

void OStreamFormatChecker::checkEndFunction(const ReturnStmt *,
                                            CheckerContext &C) const {

  ProgramStateRef S = C.getState();
  const ASTContext &AC = C.getASTContext();

  initIdents(AC);

  const FunctionDecl *Scope = getContextAsFunc(C);

  // We iterate over the map, checking whether we are
  // in the same scope as one of the tracked objects, and
  // if it is not in default state.
  // In such case, emit a warning.

  OstreamStateMapTy Streams = S->get<OstreamStateMap>();

  SmallVector<const MemRegion *, 4> ExpiredStreams;
  SmallFormatVec ForgottenStreams;

  for (const auto MapItem : Streams) {
    auto StreamState = MapItem.second;
    if (StreamState.getScope() != Scope)
      continue;

    ExpiredStreams.push_back(MapItem.first);

    if (StreamState.isDefault())
      continue;

    ForgottenStreams.push_back(MapItem);
  }

  for (const MemRegion *ExpiredStream : ExpiredStreams)
    S = S->remove<OstreamStateMap>(ExpiredStream);

  if (ForgottenStreams.empty())
    return;

  ExplodedNode *warningNode = C.generateNonFatalErrorNode(S);
  if (!warningNode)
    return;

  reportFormatWarning(ForgottenStreams, warningNode, C);
}

void OStreamFormatChecker::checkPreCall(const CallEvent &CE,
                                        CheckerContext &C) const {

  ProgramStateRef S = C.getState();
  const ASTContext &AC = C.getASTContext();

  initIdents(AC);

  // We only check ostream objects.

  // First we check if this CallEvent is a MemberCall.
  const auto *MC = dyn_cast<CXXMemberCall>(&CE);
  if (MC) {
    // There must be a CXXThisExpr since *MC is valid.
    // IgnoreCasts does not produce nullptr from a non-nullptr.
    const IdentifierInfo *ObjectII =
        MC->getCXXThisExpr()->IgnoreCasts()->getType().getBaseTypeIdentifier();
    if (ObjectII != II_BasicOstream)
      return;

    S = checkForMemberCall(MC, S, C);
  }

  // Then we check for manipulators.
  const auto *OC = dyn_cast_or_null<CXXOperatorCallExpr>(CE.getOriginExpr());
  if (OC) {
    const IdentifierInfo *Arg0II =
        OC->getArg(0)->getType().getBaseTypeIdentifier();
    if (Arg0II != II_BasicOstream)
      return;

    S = checkForManipulator(OC, S, C);
  }

  C.addTransition(S);
}

ProgramStateRef OStreamFormatChecker::checkForManipulator(
    const CXXOperatorCallExpr *OC, ProgramStateRef S, CheckerContext &C) const {

  // The check for manipulators is done by checking the operator<< calls.

  // Specificly, it is the '<<' operator.
  if (OC->getOperator() != clang::OverloadedOperatorKind::OO_LessLess)
    return S;

  // In most sensible usecases it has 2 arguments, but check it to be sure.
  if (OC->getNumArgs() != 2)
    return S;

  S = checkForSimpleManip(OC, S, C);
  S = checkForComplexManip(OC, S, C);

  return S;
}

// Check for modifications that are results of simple manipulator expressions
// embedded in left shift operator chains that have no parameters
// e.g. std::cout << std::hex.
ProgramStateRef
OStreamFormatChecker::checkForSimpleManip(const CXXOperatorCallExpr *LeftShift,
                                          ProgramStateRef S,
                                          CheckerContext &C) const {

  // The right hand side of the operator is what we are interested in.
  const auto *SimpleManip =
      dyn_cast<DeclRefExpr>(LeftShift->getArg(1)->IgnoreCasts());
  if (!SimpleManip)
    return S;

  const NamedDecl *SimpleDecl = SimpleManip->getFoundDecl();

  const auto *SimpleFuncDecl = dyn_cast_or_null<FunctionDecl>(SimpleDecl);
  if (!SimpleFuncDecl)
    return S;

  return handleSimpleManip(LeftShift, SimpleFuncDecl, S, C);
}

// Used for setprecision, and setiosflags calls.
ProgramStateRef
OStreamFormatChecker::checkForComplexManip(const CXXOperatorCallExpr *LeftShift,
                                           ProgramStateRef S,
                                           CheckerContext &C) const {
  const auto *ConstructExpr = dyn_cast<CXXConstructExpr>(LeftShift->getArg(1));

  // The test header yields a MaterializeTemporaryExpr directly.
  const auto *MTE = dyn_cast<MaterializeTemporaryExpr>(LeftShift->getArg(1));

  // If its neither, don`t continue.
  if (!ConstructExpr && !MTE)
    return S;

  // If we have CE, try to get MTE.
  if (ConstructExpr && !MTE)
    MTE = dyn_cast<MaterializeTemporaryExpr>(ConstructExpr->getArg(0));

  // If it still fails, give up.
  if (!MTE)
    return S;

  const auto *CE = dyn_cast<CallExpr>(MTE->IgnoreCasts());
  if (!CE)
    return S;

  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return S;

  const IdentifierInfo *ComplexManipII = FD->getIdentifier();
  if (!ComplexManipII)
    return S;

  if (ComplexManipII == II_Setiosflags)
    S = handleSetiosflags(LeftShift, CE, S, C);
  if (ComplexManipII == II_Resetiosflags)
    S = handleResetiosflags(LeftShift, CE, S, C);
  if (ComplexManipII == II_SetPrecision)
    S = handleSetprecision(LeftShift, CE, S, C);

  return S;
}

ProgramStateRef OStreamFormatChecker::handleSimpleManip(
    const CXXOperatorCallExpr *OCE, const FunctionDecl *FD, ProgramStateRef S,
    CheckerContext &C) const {

  const IdentifierInfo *SimpleManipII = FD->getIdentifier();

  if (!SimpleManipII)
    return S;

  const MemRegion *StreamMemRegion = getMemRegionForFirstManipArg(OCE, C);
  if (!StreamMemRegion)
    return S;

  const StoredState *TrackedState = S->get<OstreamStateMap>(StreamMemRegion);
  const FunctionDecl *Scope = getContextAsFunc(C);

  StoredState OldState = TrackedState ? *TrackedState : StoredState(Scope);
  StoredState NewState = applyStateFlagForSetting(OldState, SimpleManipII);

  return S->set<OstreamStateMap>(StreamMemRegion, NewState);
}

ProgramStateRef OStreamFormatChecker::checkForMemberCall(
    const CXXMemberCall *MC, ProgramStateRef S, CheckerContext &C) const {
  // This call must meet some specific criteria in order to
  // qualify as a stream modification.

  // It's object argument must resolve to a valid MemRegion,
  // We use it as the unique identifier for the stream.

  const MemRegion *ThisMemRegion = MC->getCXXThisVal().getAsRegion();
  if (!ThisMemRegion)
    return S;

  const MemRegion *BMR = ThisMemRegion->getBaseRegion();

  // It must have a MethodDecl.
  // Since *MC is a valid CXXMemberCall there must
  // exist an OriginExpr as well.
  const CXXMethodDecl *MethodDecl = MC->getOriginExpr()->getMethodDecl();
  if (!MethodDecl)
    return S;

  // It must identifiable.
  const IdentifierInfo *MethodII = MethodDecl->getIdentifier();
  if (!MethodII)
    return S;

  // Effectively a switch statement on method identifiers.
  // There is no implicit conversion from pointer to int,
  // so we would need to cast the pointers. It may also be
  // more readable this way.
  if (MethodII == II_Flags)
    S = handleMethodFlags(MC, BMR, S, C);
  if (MethodII == II_Setf)
    S = handleMethodSetf(MC, BMR, S, C);
  if (MethodII == II_Unsetf)
    S = handleMethodUnsetf(MC, BMR, S, C);
  if (MethodII == II_Precision)
    S = handleMethodPrecision(MC, BMR, S, C);

  return S;
}

ProgramStateRef
OStreamFormatChecker::handleMethodFlags(const CXXMemberCall *MC,
                                        const MemRegion *BMR, ProgramStateRef S,
                                        CheckerContext &C) const {
  if (MC->getNumArgs() != 0)
    return S;

  const StoredState *TrackedState = S->get<OstreamStateMap>(BMR);
  const FunctionDecl *Scope = getContextAsFunc(C);

  StoredState OldState = TrackedState ? *TrackedState : StoredState(Scope);
  StoredState NewState = OldState.applyFlagsCalledState(true);
  return S->set<OstreamStateMap>(BMR, NewState);
}

ProgramStateRef
OStreamFormatChecker::handleMethodSetf(const CXXMemberCall *MC,
                                       const MemRegion *BMR, ProgramStateRef S,
                                       CheckerContext &C) const {

  // Check wether we have an indentifiable first argument.
  const IdentifierInfo *Arg0II = getIdentifierInfoForMethodArg(MC, 0, C);
  if (!Arg0II)
    return S;

  const StoredState *TrackedState = S->get<OstreamStateMap>(BMR);
  const FunctionDecl *Scope = getContextAsFunc(C);

  StoredState OldState = TrackedState ? *TrackedState : StoredState(Scope);
  StoredState NewState = applyStateFlagForSetting(OldState, Arg0II);

  return S->set<OstreamStateMap>(BMR, NewState);
}

ProgramStateRef OStreamFormatChecker::handleMethodUnsetf(
    const CXXMemberCall *MC, const MemRegion *BMR, ProgramStateRef S,
    CheckerContext &C) const {

  // Check wether we have an indentifiable first argument.
  const IdentifierInfo *Arg0II = getIdentifierInfoForMethodArg(MC, 0, C);
  if (!Arg0II)
    return S;

  const StoredState *TrackedState = S->get<OstreamStateMap>(BMR);
  const FunctionDecl *Scope = getContextAsFunc(C);

  StoredState OldState = TrackedState ? *TrackedState : StoredState(Scope);
  StoredState NewState = applyStateFlagForUnsetting(OldState, Arg0II);

  return S->set<OstreamStateMap>(BMR, NewState);
}

ProgramStateRef OStreamFormatChecker::handleMethodPrecision(
    const CXXMemberCall *MC, const MemRegion *BMR, ProgramStateRef S,
    CheckerContext &C) const {
  if (MC->getNumArgs() != 1)
    return S;

  const Expr *Arg0 = MC->getArgExpr(0);

  Optional<int> EvaluatedValue = tryEvaluateAsInt(Arg0, S, C);
  if (!EvaluatedValue)
    return S;

  int Precision = *EvaluatedValue;

  const StoredState *TrackedState = S->get<OstreamStateMap>(BMR);
  const FunctionDecl *Scope = getContextAsFunc(C);

  StoredState OldState = TrackedState ? *TrackedState : StoredState(Scope);
  StoredState NewState = OldState.applyPrecisionState(Precision);

  return S->set<OstreamStateMap>(BMR, NewState);
}

ProgramStateRef
OStreamFormatChecker::handleSetiosflags(const CXXOperatorCallExpr *OCE,
                                        const CallExpr *CE, ProgramStateRef S,
                                        CheckerContext &C) const {

  if (CE->getNumArgs() < 1)
    return S;

  const auto *ManipArg0 = dyn_cast<DeclRefExpr>(CE->getArg(0)->IgnoreCasts());
  if (!ManipArg0)
    return S;

  const NamedDecl *ManipArgDecl = ManipArg0->getFoundDecl();
  if (!ManipArgDecl)
    return S;

  const IdentifierInfo *ManipArgII = ManipArgDecl->getIdentifier();
  if (!ManipArgDecl)
    return S;

  const MemRegion *StreamMemRegion = getMemRegionForFirstManipArg(OCE, C);
  if (!StreamMemRegion)
    return S;

  const StoredState *TrackedState = S->get<OstreamStateMap>(StreamMemRegion);
  const FunctionDecl *Scope = getContextAsFunc(C);

  StoredState OldState = TrackedState ? *TrackedState : StoredState(Scope);
  StoredState NewState = applyStateFlagForSetting(OldState, ManipArgII);

  return S->set<OstreamStateMap>(StreamMemRegion, NewState);
}

ProgramStateRef
OStreamFormatChecker::handleResetiosflags(const CXXOperatorCallExpr *OCE,
                                          const CallExpr *CE, ProgramStateRef S,
                                          CheckerContext &C) const {

  if (CE->getNumArgs() < 1)
    return S;

  const auto *ManipArg0 = dyn_cast<DeclRefExpr>(CE->getArg(0)->IgnoreCasts());
  if (!ManipArg0)
    return S;

  const NamedDecl *ManipArgDecl = ManipArg0->getFoundDecl();
  if (!ManipArgDecl)
    return S;

  const IdentifierInfo *ManipArgII = ManipArgDecl->getIdentifier();
  if (!ManipArgDecl)
    return S;

  const MemRegion *StreamMemRegion = getMemRegionForFirstManipArg(OCE, C);
  if (!StreamMemRegion)
    return S;

  const StoredState *TrackedState = S->get<OstreamStateMap>(StreamMemRegion);
  const FunctionDecl *Scope = getContextAsFunc(C);

  StoredState OldState = TrackedState ? *TrackedState : StoredState(Scope);
  StoredState NewState = applyStateFlagForUnsetting(OldState, ManipArgII);

  return S->set<OstreamStateMap>(StreamMemRegion, NewState);
}

ProgramStateRef
OStreamFormatChecker::handleSetprecision(const CXXOperatorCallExpr *OCE,
                                         const CallExpr *CE, ProgramStateRef S,
                                         CheckerContext &C) const {

  if (CE->getNumArgs() < 1)
    return S;

  const Expr *ManipArg0 = CE->getArg(0)->IgnoreCasts();
  if (!ManipArg0)
    return S;

  // Try to evaluate the argument, so we can reason about the
  // new precision value.
  Optional<int> EvaluatedValue = tryEvaluateAsInt(ManipArg0, S, C);
  if (!EvaluatedValue)
    return S;

  int Precision = *EvaluatedValue;

  const MemRegion *StreamMemRegion = getMemRegionForFirstManipArg(OCE, C);
  if (!StreamMemRegion)
    return S;

  const StoredState *TrackedState = S->get<OstreamStateMap>(StreamMemRegion);
  const FunctionDecl *Scope = getContextAsFunc(C);

  StoredState OldState = TrackedState ? *TrackedState : StoredState(Scope);
  StoredState NewState = OldState.applyPrecisionState(Precision);

  return S->set<OstreamStateMap>(StreamMemRegion, NewState);
}

StoredState OStreamFormatChecker::applyStateFlagForSetting(
    const StoredState &OldState, const IdentifierInfo *Modifier) const {

  if (Modifier == II_Hex)
    return OldState.applyNumericState(NumericFormat::HEX);
  if (Modifier == II_Dec)
    return OldState.applyNumericState(NumericFormat::DEC);
  if (Modifier == II_Oct)
    return OldState.applyNumericState(NumericFormat::OCT);
  if (Modifier == II_Left)
    return OldState.applyJustificationState(Justification::LEFT);
  if (Modifier == II_Right)
    return OldState.applyJustificationState(Justification::RIGHT);
  if (Modifier == II_Internal)
    return OldState.applyJustificationState(Justification::INTERNAL);
  if (Modifier == II_BoolAlpha)
    return OldState.applyBoolAlphaState(true);
  if (Modifier == II_NoBoolAlpha)
    return OldState.applyBoolAlphaState(false);
  if (Modifier == II_ShowPos)
    return OldState.applyShowPosState(true);
  if (Modifier == II_NoShowPos)
    return OldState.applyShowPosState(false);
  if (Modifier == II_ShowBase)
    return OldState.applyShowBaseState(true);
  if (Modifier == II_NoShowBase)
    return OldState.applyShowBaseState(false);
  if (Modifier == II_UpperCase)
    return OldState.applyUpperCaseState(true);
  if (Modifier == II_NoUpperCase)
    return OldState.applyUpperCaseState(false);
  if (Modifier == II_ShowPoint)
    return OldState.applyShowPointState(true);
  if (Modifier == II_NoShowPoint)
    return OldState.applyShowPointState(true);
  if (Modifier == II_Fixed)
    return OldState.applyFloatingPointState(FloatingPoint::FIXED);
  if (Modifier == II_Scientific)
    return OldState.applyFloatingPointState(FloatingPoint::SCIENTIFIC);

  return OldState;
}

StoredState OStreamFormatChecker::applyStateFlagForUnsetting(
    const StoredState &OldState, const IdentifierInfo *Modifier) const {

  if (Modifier == II_Hex || Modifier == II_Dec || Modifier == II_Oct)
    return OldState.applyNumericState(NumericFormat::DEC);
  if (Modifier == II_Left || Modifier == II_Right || Modifier == II_Internal)
    return OldState.applyJustificationState(Justification::LEFT);
  if (Modifier == II_BoolAlpha)
    return OldState.applyBoolAlphaState(false);
  if (Modifier == II_ShowPos)
    return OldState.applyShowPosState(false);
  if (Modifier == II_ShowBase)
    return OldState.applyShowBaseState(false);
  if (Modifier == II_UpperCase)
    return OldState.applyUpperCaseState(false);
  if (Modifier == II_ShowPoint)
    return OldState.applyShowPointState(false);

  // Fixed and Scientific flags cannot be easily reset, only
  // with an expression like .unsetf(FIXED | SCIENTIFIC).
  // A more elaborate check could be implemented for this case.
  if (Modifier == II_Fixed || Modifier == II_Scientific)
    return OldState.applyFloatingPointState(FloatingPoint::NOT_SET);

  return OldState;
}
/*
void ento::registerOStreamFormatChecker(CheckerManager &mgr) {
  mgr.registerChecker<OStreamFormatChecker>();
}
*/
void ento::registerOStreamFormatChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<OStreamFormatChecker>();
}

bool ento::shouldRegisterOStreamFormatChecker(const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
