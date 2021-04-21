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

//===-- SplitCriticalSectionsChecker.cpp --------------------------*- C++ -*--//
//
// Defines a checker for reading a variable in a critical section which got its
// value in a previous one. Between the two critical sections the variable may
// become unreliable.
//
//===----------------------------------------------------------------------===//
//
// The checker reports a bug if all of the following applies:
// - A value is assigned to a memory location (e.g. variable or part of a
//   variable) in a critical section, protected by at least one mutex
//   (`pthread_mutex` or C++ 11 `std::mutex`).
// - The same memory location is read in another critical section, protected
//   exactly by the same set of mutexes.
// - These read and write operations are in the same function, thus merging the
//   two critical sections is technically possible.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {

// Data for a location bound in a critical section. It stores the set of
// mutexes which were locked at the time of the assignment, the function where
// the assignment happened, and a validity flag which remains true until at
// least one mutex (which was locked at the time of the assignments) gets
// unlocked.
struct BoundVarLockData {
private:
  bool Valid;
  llvm::ImmutableSet<const MemRegion *> Mutexes;
  const FunctionDecl *ParentFunc;
  BoundVarLockData(bool V, const llvm::ImmutableSet<const MemRegion *> &M,
                   const FunctionDecl *PF)
      : Valid(V), Mutexes(M), ParentFunc(PF) {}

public:
  bool contains(const MemRegion *Mutex) const {
    return Mutexes.contains(Mutex);
  }

  bool sameMutexes(const llvm::ImmutableSet<const MemRegion *> &M) const {
    return M == Mutexes;
  }

  bool isValid() const { return Valid; }

  const FunctionDecl *getParentFunction() const { return ParentFunc; }

  BoundVarLockData invalidate() const {
    return BoundVarLockData(false, Mutexes, ParentFunc);
  }

  static BoundVarLockData
  getData(const llvm::ImmutableSet<const MemRegion *> &M,
          const FunctionDecl *PF) {
    return BoundVarLockData(true, M, PF);
  }

  bool operator==(const BoundVarLockData &X) const {
    return Valid == X.Valid && Mutexes == X.Mutexes &&
           ParentFunc == X.ParentFunc;
  }

  bool operator!=(const BoundVarLockData &X) const { return !(*this == X); }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(Valid);
    ID.Add(Mutexes);
    ID.AddPointer(ParentFunc);
  }
};

class SplitCriticalSectionsChecker
    : public Checker<check::PostCall, check::Bind, check::Location,
                     check::DeadSymbols> {
public:
  SplitCriticalSectionsChecker() = default;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;

private:
  mutable std::unique_ptr<BugType> SplitCriticalSectionsBugType;

  void reportBug(const StringRef Message, const MemRegion *Reg,
                 CheckerContext &C, ExplodedNode *ErrNode) const;
};

} // namespace

REGISTER_SET_WITH_PROGRAMSTATE(LockedMutexSet, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(BoundVarMap, const MemRegion *, BoundVarLockData)

namespace {

class SplitCriticalSectionsBRVisitor final : public BugReporterVisitor {
  const MemRegion *Reg;

public:
  explicit SplitCriticalSectionsBRVisitor(const MemRegion *R) : Reg(R) {}

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    ID.AddPointer(Reg);
  }

PathDiagnosticPieceRef VisitNode(const ExplodedNode *Succ,
                                 BugReporterContext &BRC,
                                 PathSensitiveBugReport &BR) override;
};

// Utility Functions

bool hasCXXMutexType(const Expr *Ex);
bool isCXXLockMethod(const FunctionDecl *Func);
bool isCXXUnlockMethod(const FunctionDecl *Func);
bool isLockFunction(const FunctionDecl *Func);
bool isUnlockFunction(const FunctionDecl *Func);
ProgramStateRef lockMutex(ProgramStateRef State, SVal Mutex);
ProgramStateRef unlockMutex(ProgramStateRef State, SVal Mutex);
ProgramStateRef invalidateBoundVariables(ProgramStateRef State, SVal Mutex);
bool becameBound(ProgramStateRef State, ProgramStateRef PrevState,
                 const MemRegion *Reg);
bool becameInvalidated(ProgramStateRef State, ProgramStateRef PrevState,
                       const MemRegion *Reg);
bool sameMutexesBecameLockedFor(ProgramStateRef State,
                                ProgramStateRef PrevState,
                                const MemRegion *Reg);
bool isSelfModification(const ProgramStateRef State,
                        const LocationContext *LCtx, const Stmt *S,
                        const MemRegion *Reg);
} // namespace

void SplitCriticalSectionsChecker::checkPostCall(const CallEvent &Call,
                                                 CheckerContext &C) const {
  const auto *Func = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!Func)
    return;

  auto State = C.getState();

  if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
    // The type of the `this` pointer in C++ destructors may be invalid
    if (isa<CXXDestructorDecl>(Func))
      return;

    if (hasCXXMutexType(InstCall->getCXXThisExpr())) {
      if (isCXXLockMethod(Func)) {
        State = lockMutex(State, InstCall->getCXXThisVal());
      } else if (isCXXUnlockMethod(Func)) {
        State = unlockMutex(State, InstCall->getCXXThisVal());
        State = invalidateBoundVariables(State, InstCall->getCXXThisVal());
      }
    }
  } else {
    if (isLockFunction(Func)) {
      State = lockMutex(State, Call.getArgSVal(0));
    } else if (isUnlockFunction(Func)) {
      State = unlockMutex(State, Call.getArgSVal(0));
      State = invalidateBoundVariables(State, Call.getArgSVal(0));
    }
  }

  C.addTransition(State);
  return;
}

void SplitCriticalSectionsChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                             CheckerContext &C) const {
  const auto *Reg = Loc.getAsRegion();
  if (!Reg)
    return;

  auto State = C.getState();
  const auto MutSet = State->get<LockedMutexSet>();

  const auto *Func = C.getLocationContext()->getDecl()->getAsFunction();

  // Only care for locations bound in a critical section in a function
  if (!MutSet.isEmpty() && Func) {
    State =
        State->set<BoundVarMap>(Reg, BoundVarLockData::getData(MutSet, Func));
  } else {
    State = State->remove<BoundVarMap>(Reg);
  }
  C.addTransition(State);
}

void SplitCriticalSectionsChecker::checkLocation(SVal Loc, bool IsLoad,
                                                 const Stmt *S,
                                                 CheckerContext &C) const {
  if (!IsLoad)
    return;

  const auto *Reg = Loc.getAsRegion();
  if (!Reg)
    return;

  auto State = C.getState();

  // The variable must have been bound in a critical section.
  const auto *BVD = State->get<BoundVarMap>(Reg);
  if (!BVD || BVD->isValid())
    return;

  // It must also be in this same function.
  if (BVD->getParentFunction() !=
      C.getLocationContext()->getDecl()->getAsFunction())
    return;

  // We must be in a critical section as well.
  const auto MutSet = State->get<LockedMutexSet>();
  if (MutSet.isEmpty())
    return;

  // This critical section must have exactly the same set of mutexes locked.
  if (!BVD->sameMutexes(MutSet))
    return;

  // If it is a self modification of the variable (e.g. increment or decrement)
  // ignore it (typical for counters).
  if (isSelfModification(State, C.getLocationContext(), S, Reg))
    return;

  auto *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  reportBug("Using of unreliable value in the second critical section", Reg, C,
            N);
}

void SplitCriticalSectionsChecker::reportBug(const StringRef Message,
                                             const MemRegion *Reg,
                                             CheckerContext &C,
                                             ExplodedNode *ErrNode) const {
  if (!SplitCriticalSectionsBugType) {
    SplitCriticalSectionsBugType.reset(new BugType(
        getCheckerName(), "Data in variable unreliable", "Concurrency"));
  }

  auto R = std::make_unique<PathSensitiveBugReport>(
      *SplitCriticalSectionsBugType, Message, ErrNode);
  R->markInteresting(Reg);
  R->addVisitor(std::make_unique<SplitCriticalSectionsBRVisitor>(Reg));
  C.emitReport(std::move(R));
}

void SplitCriticalSectionsChecker::checkDeadSymbols(SymbolReaper &SR,
                                                    CheckerContext &C) const {
  // Cleanup
  auto State = C.getState();

  for (const auto &BVD : State->get<BoundVarMap>()) {
    if (!SR.isLiveRegion(BVD.first)) {
      State = State->remove<BoundVarMap>(BVD.first);
    }
  }

  for (const auto Mutex : State->get<LockedMutexSet>()) {
    if (!SR.isLiveRegion(Mutex)) {
      State = State->remove<BoundVarMap>(Mutex);
    }
  }
}

PathDiagnosticPieceRef SplitCriticalSectionsBRVisitor::VisitNode(
    const ExplodedNode *Succ, BugReporterContext &BRC,
    PathSensitiveBugReport &BR) {
  const ExplodedNode *Pred = Succ->getFirstPred();
  const auto &State = Succ->getState();
  const auto &PrevState = Pred->getState();

  const auto SP = Succ->getLocation().getAs<StmtPoint>();
  if (!SP.hasValue())
    return nullptr;

  const auto *S = SP->getStmt();

  SmallString<256> Buf;
  llvm::raw_svector_ostream Out(Buf);

  // Mark the point of the assignment, the point of the first mutex unlocked
  // and the last mutex relocked
  if (becameBound(State, PrevState, Reg)) {
    Out << "Value is assigned here";
  } else if (becameInvalidated(State, PrevState, Reg)) {
    Out << "First critical section ends here";
  } else if (sameMutexesBecameLockedFor(State, PrevState, Reg)) {
    Out << "Second critical section begins here";
  }

  if (Buf.empty())
    return nullptr;

  auto L = PathDiagnosticLocation::createBegin(S, BRC.getSourceManager(),
                                               Succ->getLocationContext());
  if (!L.isValid() || !L.asLocation().isValid())
    return nullptr;

  auto Piece = std::make_shared<PathDiagnosticEventPiece>(L, Out.str());
  Piece->addRange(S->getSourceRange());

  return Piece;
}

// Utility function implementations

namespace {
const Stmt *getSurroundingStoreStatement(const ProgramStateRef State,
                                         const Stmt *S);

bool hasCXXMutexType(const Expr *Ex) {
  const auto QT = Ex->getType();
  const auto *Rec = QT->getAsCXXRecordDecl();
  if (!Rec)
    return false;

  if (!Rec->isInStdNamespace())
    return false;

  const auto *IdInfo = Rec->getIdentifier();
  if (!IdInfo)
    return false;

  return IdInfo->getName() == "mutex";
}

bool isCXXLockMethod(const FunctionDecl *Func) {
  if (Func->getNumParams() > 0)
    return false;

  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;

  return IdInfo->getName() == "lock";
}

bool isCXXUnlockMethod(const FunctionDecl *Func) {
  if (Func->getNumParams() > 0)
    return false;

  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;

  return IdInfo->getName() == "unlock";
}

bool isLockFunction(const FunctionDecl *Func) {
  if (!isa<TranslationUnitDecl>(Func->getDeclContext()) &&
      !Func->isInStdNamespace())
    return false;

  if (Func->getNumParams() != 1)
    return false;

  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;

  return IdInfo->getName() == "pthread_mutex_lock";
}

bool isUnlockFunction(const FunctionDecl *Func) {
  if (!isa<TranslationUnitDecl>(Func->getDeclContext()) &&
      !Func->isInStdNamespace())
    return false;

  if (Func->getNumParams() != 1)
    return false;

  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;

  return IdInfo->getName() == "pthread_mutex_unlock";
}

ProgramStateRef lockMutex(ProgramStateRef State, SVal Mutex) {
  if (const auto *Reg = Mutex.getAsRegion()) {
    return State->add<LockedMutexSet>(Reg);
  }
  return State;
}

ProgramStateRef unlockMutex(ProgramStateRef State, SVal Mutex) {
  if (const auto *Reg = Mutex.getAsRegion()) {
    return State->remove<LockedMutexSet>(Reg);
  }
  return State;
}

ProgramStateRef invalidateBoundVariables(ProgramStateRef State, SVal Mutex) {
  const auto *Reg = Mutex.getAsRegion();
  if (!Reg)
    return State;

  for (const auto &BVD : State->get<BoundVarMap>()) {
    if (BVD.second.contains(Reg)) {
      State = State->set<BoundVarMap>(BVD.first, BVD.second.invalidate());
    }
  }

  return State;
}

bool becameBound(ProgramStateRef State, ProgramStateRef PrevState,
                 const MemRegion *Reg) {
  const auto *Cur = State->get<BoundVarMap>(Reg);
  if (!Cur || !Cur->isValid())
    return false;

  const auto *Prev = PrevState->get<BoundVarMap>(Reg);
  if (!Prev)
    return true;

  return *Cur != *Prev;
}

bool becameInvalidated(ProgramStateRef State, ProgramStateRef PrevState,
                       const MemRegion *Reg) {
  const auto *Cur = State->get<BoundVarMap>(Reg);
  const auto *Prev = PrevState->get<BoundVarMap>(Reg);
  if (!Cur || !Prev)
    return false;

  return !Cur->isValid() && Prev->isValid();
}

bool sameMutexesBecameLockedFor(ProgramStateRef State,
                                ProgramStateRef PrevState,
                                const MemRegion *Reg) {
  const auto *Cur = State->get<BoundVarMap>(Reg);
  if (!Cur || Cur->isValid())
    return false;

  const auto Mutexes = State->get<LockedMutexSet>();
  if (Mutexes.isEmpty())
    return false;

  const auto PrevMutexes = PrevState->get<LockedMutexSet>();

  return Cur->sameMutexes(Mutexes) && Mutexes != PrevMutexes;
}

bool isSelfModification(const ProgramStateRef State,
                        const LocationContext *LCtx, const Stmt *S,
                        const MemRegion *Reg) {
  const auto *SS = getSurroundingStoreStatement(State, S);
  if (const auto *UO = dyn_cast<UnaryOperator>(SS)) {
    if (UO->isIncrementDecrementOp()) {
      const auto *SE = UO->getSubExpr();
      if (const auto *SReg = State->getSVal(SE, LCtx).getAsRegion())
        return SReg == Reg;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(SS)) {
    if (BO->isAssignmentOp()) {
      const auto *LHS = BO->getLHS();
      if (const auto *LReg = State->getSVal(LHS, LCtx).getAsRegion()) {
        return LReg == Reg;
      }
    }
  }

  return false;
}

const Stmt *getSurroundingStoreStatement(const ProgramStateRef State,
                                         const Stmt *S) {
  auto &AC = State->getStateManager().getContext();
  const auto *Cur = S;
  while (true) {
    auto Parents = AC.getParents(*Cur);
    if (Parents.empty())
      return Cur;

    if (isa<CompoundStmt>(Parents[0].get<Stmt>()))
      return Cur;

    Cur = Parents[0].get<Stmt>();
    if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
      if (UO->isIncrementDecrementOp())
        return Cur;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(Cur)) {
      if (BO->isAssignmentOp())
        return Cur;
    }
  }
  return Cur;
}

} // namespace

void ento::registerSplitCriticalSectionsChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<SplitCriticalSectionsChecker>();
}

bool ento::shouldRegisterSplitCriticalSectionsChecker(
    const CheckerManager &mgr) {
  return true;
}
