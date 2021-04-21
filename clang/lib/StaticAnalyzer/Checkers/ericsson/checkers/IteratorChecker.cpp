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

//===-- IteratorChecker.cpp ---------------------------------------*- C++ -*--//
//
// Defines a checker for using iterators outside their range (past end). Usage
// means here dereferencing, incrementing etc.
//
//===----------------------------------------------------------------------===//
//
// In the code, iterator can be represented as a:
// * type-I: typedef-ed pointer. Operations over such iterator, such as
//           comparisons or increments, are modeled straightforwardly by the
//           analyzer.
// * type-II: structure with its method bodies available.  Operations over such
//            iterator are inlined by the analyzer, and results of modeling
//            these operations are exposing implementation details of the
//            iterators, which is not necessarily helping.
// * type-III: completely opaque structure. Operations over such iterator are
//             modeled conservatively, producing conjured symbols everywhere.
//
// To handle all these types in a common way we introduce a structure called
// IteratorPosition which is an abstraction of the position the iterator
// represents using symbolic expressions. The checker handles all the
// operations on this structure.
//
// Additionally, depending on the circumstances, operators of types II and III
// can be represented as:
// * type-IIa, type-IIIa: conjured structure symbols - when returned by value
//                        from conservatively evaluated methods such as
//                        `.begin()`.
// * type-IIb, type-IIIb: memory regions of iterator-typed objects, such as
//                        variables or temporaries, when the iterator object is
//                        currently treated as an lvalue.
// * type-IIc, type-IIIc: compound values of iterator-typed objects, when the
//                        iterator object is treated as an rvalue taken of a
//                        particular lvalue, eg. a copy of "type-a" iterator
//                        object, or an iterator that existed before the
//                        analysis has started.
//
// To handle any of these three different representations stored in an SVal we
// use setter and getters functions which separate the three cases. To store
// them we use a pointer union of symbol and memory region.
//
// The checker works the following way: We record the begin and the
// past-end iterator for all containers whenever their `.begin()` and `.end()`
// are called. Since the Constraint Manager cannot handle such SVals we need
// to take over its role. We post-check equality and non-equality comparisons
// and record that the two sides are equal if we are in the 'equal' branch
// (true-branch for `==` and false-branch for `!=`).
//
// In case of type-I or type-II iterators we get a concrete integer as a result
// of the comparison (1 or 0) but in case of type-III we only get a Symbol. In
// this latter case we record the symbol and reload it in evalAssume() and do
// the propagation there. We also handle (maybe double) negated comparisons
// which are represented in the form of (x == 0 or x != 0) where x is the
// comparison itself.
//
// Since `SimpleConstraintManager` cannot handle complex symbolic expressions
// we only use expressions of the format S, S+n or S-n for iterator positions
// where S is a conjured symbol and n is an unsigned concrete integer. When
// making an assumption e.g. `S1 + n == S2 + m` we store `S1 - S2 == m - n` as
// a constraint which we later retrieve when doing an actual comparison.

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include <utility>

using namespace clang;
using namespace ento;

namespace {

// Abstract position of an iterator. This helps to handle all three kinds
// of operators in a common way by using a symbolic position.
struct IteratorPosition {
private:
  // Container the iterator belongs to
  const MemRegion *Cont;

  // Whether iterator is valid
  bool Valid;

  // Abstract offset
  const SymbolRef Offset;

  IteratorPosition(const MemRegion *C, bool V, SymbolRef Of)
      : Cont(C), Valid(V), Offset(Of) {}

public:
  const MemRegion *getContainer() const { return Cont; }
  bool isValid() const { return Valid; }
  SymbolRef getOffset() const { return Offset; }

  IteratorPosition invalidate() const {
    return IteratorPosition(Cont, false, Offset);
  }

  static IteratorPosition getPosition(const MemRegion *C, SymbolRef Of) {
    return IteratorPosition(C, true, Of);
  }

  IteratorPosition setTo(SymbolRef NewOf) const {
    return IteratorPosition(Cont, Valid, NewOf);
  }

  IteratorPosition reAssign(const MemRegion *NewCont) const {
    return IteratorPosition(NewCont, Valid, Offset);
  }

  bool operator==(const IteratorPosition &X) const {
    return Cont == X.Cont && Valid == X.Valid && Offset == X.Offset;
  }

  bool operator!=(const IteratorPosition &X) const {
    return Cont != X.Cont || Valid != X.Valid || Offset != X.Offset;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Cont);
    ID.AddInteger(Valid);
    ID.Add(Offset);
  }
};

// Structure to record the symbolic begin and end position of a container
struct ContainerData {
private:
  const SymbolRef Begin, End;

  ContainerData(SymbolRef B, SymbolRef E) : Begin(B), End(E) {}

public:
  static ContainerData fromBegin(SymbolRef B) {
    return ContainerData(B, nullptr);
  }

  static ContainerData fromEnd(SymbolRef E) {
    return ContainerData(nullptr, E);
  }

  SymbolRef getBegin() const { return Begin; }
  SymbolRef getEnd() const { return End; }

  ContainerData newBegin(SymbolRef B) const { return ContainerData(B, End); }

  ContainerData newEnd(SymbolRef E) const { return ContainerData(Begin, E); }

  bool operator==(const ContainerData &X) const {
    return Begin == X.Begin && End == X.End;
  }

  bool operator!=(const ContainerData &X) const {
    return Begin != X.Begin || End != X.End;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.Add(Begin);
    ID.Add(End);
  }
};

class IteratorChecker
    : public Checker<check::PreCall, check::PostCall,
                     check::PreStmt<CXXConstructExpr>,
                     check::PostStmt<MaterializeTemporaryExpr>, check::Bind,
                     check::BeginFunction, check::LiveSymbols,
                     check::DeadSymbols, eval::Call> {
  mutable IdentifierInfo *II_find = nullptr, *II_find_end = nullptr,
                         *II_find_first_of = nullptr, *II_find_if = nullptr,
                         *II_find_if_not = nullptr, *II_lower_bound = nullptr,
                         *II_upper_bound = nullptr, *II_search = nullptr,
                         *II_search_n = nullptr;

  mutable std::unique_ptr<BugType> OutOfRangeBugType;
  mutable std::unique_ptr<BugType> MismatchedBugType;
  mutable std::unique_ptr<BugType> InvalidatedBugType;

  void handleComparison(CheckerContext &C, const Expr *CE, SVal RetVal,
                        const SVal &LVal, const SVal &RVal,
                        OverloadedOperatorKind Op) const;
  void handleEmpty(CheckerContext &C, const Expr *CE, const SVal &RetVal,
                   const SVal &Cont) const;
  void processComparison(CheckerContext &C, ProgramStateRef State,
                         SymbolRef Sym1, SymbolRef Sym2, const SVal &RetVal,
                         OverloadedOperatorKind Op) const;
  void verifyAccess(CheckerContext &C, const SVal &Val) const;
  void verifyDereference(CheckerContext &C, const SVal &Val) const;
  void handleIncrement(CheckerContext &C, const SVal &RetVal, const SVal &Iter,
                       bool Postfix) const;
  void handleDecrement(CheckerContext &C, const SVal &RetVal, const SVal &Iter,
                       bool Postfix) const;
  void handleRandomIncrOrDecr(CheckerContext &C, OverloadedOperatorKind Op,
                              const SVal &RetVal, const SVal &LHS,
                              const SVal &RHS) const;
  void handleIteratorAssign(CheckerContext &C, const SVal &NewIter,
                            const SVal &OldIter, const SVal &RetVal) const;
  void handleBegin(CheckerContext &C, const Expr *CE, const SVal &RetVal,
                   const SVal &Cont) const;
  void handleEnd(CheckerContext &C, const Expr *CE, const SVal &RetVal,
                 const SVal &Cont) const;
  void assignToContainer(CheckerContext &C, const Expr *CE, const SVal &RetVal,
                         const MemRegion *Cont) const;
  void handleContainerAssign(CheckerContext &C, const SVal &Cont,
                             const Expr *CE = nullptr,
                             const SVal &OldCont = UndefinedVal()) const;
  void handleClear(CheckerContext &C, const SVal &Cont) const;
  void handlePushBack(CheckerContext &C, const SVal &Cont) const;
  void handlePopBack(CheckerContext &C, const SVal &Cont) const;
  void handlePushFront(CheckerContext &C, const SVal &Cont) const;
  void handlePopFront(CheckerContext &C, const SVal &Cont) const;
  void handleInsert(CheckerContext &C, const SVal &Iter) const;
  void handleErase(CheckerContext &C, const SVal &Iter, const SVal &RetVal,
                   const Expr *CE) const;
  void handleErase(CheckerContext &C, const SVal &Iter1, const SVal &Iter2,
                   const SVal &RetVal) const;
  void handleEraseAfter(CheckerContext &C, const SVal &Iter,
                        const SVal &RetVal) const;
  void handleEraseAfter(CheckerContext &C, const SVal &Iter1, const SVal &Iter2,
                        const SVal &RetVal) const;
  void verifyIncrement(CheckerContext &C, const SVal &Iter) const;
  void verifyDecrement(CheckerContext &C, const SVal &Iter) const;
  void verifyRandomIncrOrDecr(CheckerContext &C, OverloadedOperatorKind Op,
                              const SVal &LHS, const SVal &RHS) const;
  void verifyMatch(CheckerContext &C, const SVal &Iter,
                   const MemRegion *Cont) const;
  void verifyMatch(CheckerContext &C, const SVal &Iter1,
                   const SVal &Iter2) const;
  bool evalFind(CheckerContext &C, const CallExpr *CE) const;
  bool evalFindEnd(CheckerContext &C, const CallExpr *CE) const;
  bool evalFindFirstOf(CheckerContext &C, const CallExpr *CE) const;
  bool evalFindIf(CheckerContext &C, const CallExpr *CE) const;
  bool evalFindIfNot(CheckerContext &C, const CallExpr *CE) const;
  bool evalLowerBound(CheckerContext &C, const CallExpr *CE) const;
  bool evalUpperBound(CheckerContext &C, const CallExpr *CE) const;
  bool evalSearch(CheckerContext &C, const CallExpr *CE) const;
  bool evalSearchN(CheckerContext &C, const CallExpr *CE) const;
  void Find(CheckerContext &C, const CallExpr *CE) const;
  ProgramStateRef advancePosition(ProgramStateRef State,
                                  OverloadedOperatorKind Op, const SVal &Iter,
                                  const SVal &Distance,
                                  const LocationContext *LCtx,
                                  unsigned BlockCount) const;
  void reportOutOfRangeBug(const StringRef &Message, const SVal &Val,
                           CheckerContext &C, ExplodedNode *ErrNode,
                           const IteratorPosition *Pos,
                           bool PastTheEnd = true) const;
  void reportMismatchedBug(const StringRef &Message, const SVal &Val1,
                           const SVal &Val2, CheckerContext &C,
                           ExplodedNode *ErrNode) const;
  void reportMismatchedBug(const StringRef &Message, const SVal &Val,
                           const MemRegion *Reg, CheckerContext &C,
                           ExplodedNode *ErrNode) const;
  void reportInvalidatedBug(const StringRef &Message, const SVal &Val,
                            CheckerContext &C, ExplodedNode *ErrNode,
                            const IteratorPosition *Pos) const;

  void initIdentifiers(ASTContext &Ctx) const;

public:
  IteratorChecker() = default;

  enum CheckKind {
    CK_IteratorOutOfRangeChecker,
    CK_IteratorMismatchChecker,
    CK_InvalidatedIteratorAccessChecker,
    CK_NumCheckKinds
  };

  DefaultBool ChecksEnabled[CK_NumCheckKinds];
  CheckerNameRef CheckNames[CK_NumCheckKinds];

  DefaultBool AggressiveEraseModeling;

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const CXXConstructExpr *CCE, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &C) const;
  void checkPostStmt(const MaterializeTemporaryExpr *MTE,
                     CheckerContext &C) const;
  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &SR) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
};
} // namespace

// This visitor helps the user to better understand the out-of-range and the
// invalidated iterator bug types. It adds a note to the statement which
// results in the past-the-end, beginning of the range or the invalideted
// state of the iterator. Furthermore it also markes the block edges where
// we assume that the container of the iterator is empty or non-empty.
class IteratorBRVisitor final : public BugReporterVisitor {
public:
  enum ErrorTypeT { AheadOfRange, PastTheEnd, Invalidated };

private:
  SVal Iter;
  const MemRegion *Cont;

  // `FoundChange` becomes true when we find the statement the results in the
  // current state of the iterator.
  // `FoundEmptyness` becomes true when we find the block edge assuming
  // emptiness or non-emptiness of the container.
  bool FoundChange = false, FoundEmptiness;
  ErrorTypeT ErrorType;

public:
  IteratorBRVisitor(SVal It, const MemRegion *C, ErrorTypeT ET)
      : Iter(It), Cont(C), ErrorType(ET) {
    // Emptyness does not matter for invalidated iterator access
    FoundEmptiness = ErrorType == Invalidated;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    ID.Add(Iter);
    ID.Add(Cont);
    ID.AddInteger(ErrorType);
  }

  PathDiagnosticPieceRef VisitNode(const ExplodedNode *Succ,
                                   BugReporterContext &BRC,
                                   PathSensitiveBugReport &BR) override;
};

REGISTER_MAP_WITH_PROGRAMSTATE(IteratorSymbolMap, SymbolRef, IteratorPosition)
REGISTER_MAP_WITH_PROGRAMSTATE(IteratorRegionMap, const MemRegion *,
                               IteratorPosition)

REGISTER_MAP_WITH_PROGRAMSTATE(ContainerMap, const MemRegion *, ContainerData)

#define INIT_ID(Id)                                                            \
  if (!II_##Id)                                                                \
  II_##Id = &Ctx.Idents.get(#Id)
#define CI_ZERO(Bvf) nonloc::ConcreteInt((Bvf).getValue(llvm::APSInt::get(0)))
#define CI_ONE(Bvf) nonloc::ConcreteInt((Bvf).getValue(llvm::APSInt::get(1)))

namespace {

bool isIteratorType(const QualType &Type);
bool isIterator(const CXXRecordDecl *CRD);
bool isContainerTypeFor(const QualType &Type, const QualType &IteratorType);
bool isContainerFor(const CXXRecordDecl *CRD, const QualType &IteratorType);
bool isComparisonOperator(OverloadedOperatorKind OK);
bool isBeginCall(const FunctionDecl *Func);
bool isEndCall(const FunctionDecl *Func);
bool isAssignCall(const FunctionDecl *Func);
bool isClearCall(const FunctionDecl *Func);
bool isPushBackCall(const FunctionDecl *Func);
bool isEmplaceBackCall(const FunctionDecl *Func);
bool isPopBackCall(const FunctionDecl *Func);
bool isPushFrontCall(const FunctionDecl *Func);
bool isEmplaceFrontCall(const FunctionDecl *Func);
bool isPopFrontCall(const FunctionDecl *Func);
bool isInsertCall(const FunctionDecl *Func);
bool isEraseCall(const FunctionDecl *Func);
bool isEraseAfterCall(const FunctionDecl *Func);
bool isEmplaceCall(const FunctionDecl *Func);
bool isEmptyCall(const FunctionDecl *Func);
bool isStdAdvanceCall(const FunctionDecl *Func);
bool isStdPrevCall(const FunctionDecl *Func);
bool isStdNextCall(const FunctionDecl *Func);
bool isAssignmentOperator(OverloadedOperatorKind OK);
bool isSimpleComparisonOperator(OverloadedOperatorKind OK);
bool isAccessOperator(OverloadedOperatorKind OK);
bool isDereferenceOperator(OverloadedOperatorKind OK);
bool isIncrementOperator(OverloadedOperatorKind OK);
bool isDecrementOperator(OverloadedOperatorKind OK);
bool isRandomIncrOrDecrOperator(OverloadedOperatorKind OK);
bool hasSubscriptOperator(const MemRegion *Reg);
bool frontModifiable(const MemRegion *Reg);
bool backModifiable(const MemRegion *Reg);
SymbolRef getContainerBegin(ProgramStateRef State, const MemRegion *Cont);
SymbolRef getContainerEnd(ProgramStateRef State, const MemRegion *Cont);
ProgramStateRef createContainerBegin(ProgramStateRef State,
                                     const MemRegion *Cont, const Expr *E,
                                     QualType T, const LocationContext *LCtx,
                                     unsigned BlockCount);
ProgramStateRef createContainerEnd(ProgramStateRef State, const MemRegion *Cont,
                                   const Expr *E, QualType T,
                                   const LocationContext *LCtx,
                                   unsigned BlockCount);
const IteratorPosition *getIteratorPosition(ProgramStateRef State,
                                            const SVal &Val);
ProgramStateRef setIteratorPosition(ProgramStateRef State, const SVal &Val,
                                    const IteratorPosition &Pos);
ProgramStateRef removeIteratorPosition(ProgramStateRef State, const SVal &Val);
ProgramStateRef copyIteratorPosition(ProgramStateRef State, const SVal &Src,
                                     const SVal &Dest);
ProgramStateRef invalidateAllIteratorPositions(ProgramStateRef State,
                                               const MemRegion *Cont);
ProgramStateRef
invalidateAllIteratorPositionsExcept(ProgramStateRef State,
                                     const MemRegion *Cont, SymbolRef Offset,
                                     BinaryOperator::Opcode Opc);
ProgramStateRef invalidateIteratorPositions(ProgramStateRef State,
                                            SymbolRef Offset,
                                            BinaryOperator::Opcode Opc);
ProgramStateRef invalidateIteratorPositions(ProgramStateRef State,
                                            SymbolRef Offset1,
                                            BinaryOperator::Opcode Opc1,
                                            SymbolRef Offset2,
                                            BinaryOperator::Opcode Opc2);
ProgramStateRef reassignAllIteratorPositions(ProgramStateRef State,
                                             const MemRegion *Cont,
                                             const MemRegion *NewCont);
ProgramStateRef reassignAllIteratorPositionsUnless(ProgramStateRef State,
                                                   const MemRegion *Cont,
                                                   const MemRegion *NewCont,
                                                   SymbolRef Offset,
                                                   BinaryOperator::Opcode Opc);
ProgramStateRef rebaseSymbolInIteratorPositionsIf(
    ProgramStateRef State, SValBuilder &SVB, SymbolRef OldSym, SymbolRef NewSym,
    SymbolRef CondSym, BinaryOperator::Opcode Opc);
ProgramStateRef relateSymbols(ProgramStateRef State, SymbolRef Sym1,
                              SymbolRef Sym2, bool Equal);
const ContainerData *getContainerData(ProgramStateRef State,
                                      const MemRegion *Cont);
ProgramStateRef setContainerData(ProgramStateRef State, const MemRegion *Cont,
                                 const ContainerData &CData);
bool isPastTheEnd(ProgramStateRef State, const IteratorPosition &Pos);
bool isAheadOfRange(ProgramStateRef State, const IteratorPosition &Pos);
bool isBehindPastTheEnd(ProgramStateRef State, const IteratorPosition &Pos);
const MemRegion *getTopRegion(const MemRegion *Reg);
} // namespace

void IteratorChecker::checkPreCall(const CallEvent &Call,
                                   CheckerContext &C) const {
  // Check for out of range access or access of invalidated position and
  // iterator mismatches
  const auto *Func = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!Func)
    return;

  if (Func->isOverloadedOperator()) {
    if (ChecksEnabled[CK_InvalidatedIteratorAccessChecker] &&
        isAccessOperator(Func->getOverloadedOperator())) {
      // Check for any kind of access of invalidated iterator positions
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        verifyAccess(C, InstCall->getCXXThisVal());
      } else {
        verifyAccess(C, Call.getArgSVal(0));
      }
    }
    if (ChecksEnabled[CK_IteratorOutOfRangeChecker] &&
        isIncrementOperator(Func->getOverloadedOperator())) {
      // Check for out-of-range incrementions
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        verifyIncrement(C, InstCall->getCXXThisVal());
      } else {
        if (Call.getNumArgs() >= 1) {
          verifyIncrement(C, Call.getArgSVal(0));
        }
      }
    } else if (ChecksEnabled[CK_IteratorOutOfRangeChecker] &&
               isDecrementOperator(Func->getOverloadedOperator())) {
      // Check for out-of-range decrementions
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        verifyDecrement(C, InstCall->getCXXThisVal());
      } else {
        if (Call.getNumArgs() >= 1) {
          verifyDecrement(C, Call.getArgSVal(0));
        }
      }
    } else if (ChecksEnabled[CK_IteratorOutOfRangeChecker] &&
               isRandomIncrOrDecrOperator(Func->getOverloadedOperator())) {
      // Check for out-of-range incrementions and decrementions
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        if (Call.getNumArgs() >= 1 &&
            Call.getArgExpr(0)->getType()->isIntegralOrEnumerationType()) {
          verifyRandomIncrOrDecr(C, Func->getOverloadedOperator(),
                                 InstCall->getCXXThisVal(), Call.getArgSVal(0));
        }
      } else {
        if (Call.getNumArgs() >= 2 &&
            Call.getArgExpr(1)->getType()->isIntegralOrEnumerationType()) {
          verifyRandomIncrOrDecr(C, Func->getOverloadedOperator(),
                                 Call.getArgSVal(0), Call.getArgSVal(1));
        }
      }
    } else if (ChecksEnabled[CK_IteratorOutOfRangeChecker] &&
               isDereferenceOperator(Func->getOverloadedOperator())) {
      // Check for dereference of out-of-range iterators
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        verifyDereference(C, InstCall->getCXXThisVal());
      } else {
        verifyDereference(C, Call.getArgSVal(0));
      }
    } else if (ChecksEnabled[CK_IteratorMismatchChecker] &&
               isComparisonOperator(Func->getOverloadedOperator())) {
      // Check for comparisons of iterators of different containers
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        if (Call.getNumArgs() < 1)
          return;

        if (!isIteratorType(InstCall->getCXXThisExpr()->getType()) ||
            !isIteratorType(Call.getArgExpr(0)->getType()))
          return;

        verifyMatch(C, InstCall->getCXXThisVal(), Call.getArgSVal(0));
      } else {
        if (Call.getNumArgs() < 2)
          return;

        if (!isIteratorType(Call.getArgExpr(0)->getType()) ||
            !isIteratorType(Call.getArgExpr(1)->getType()))
          return;

        verifyMatch(C, Call.getArgSVal(0), Call.getArgSVal(1));
      }
    }
  } else if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
    if (!ChecksEnabled[CK_IteratorMismatchChecker])
      return;

    const auto *ContReg = InstCall->getCXXThisVal().getAsRegion();
    if (!ContReg)
      return;
    // Check for erase, insert and emplace using iterator of another container
    if (isEraseCall(Func) || isEraseAfterCall(Func)) {
      verifyMatch(C, Call.getArgSVal(0),
                  InstCall->getCXXThisVal().getAsRegion());
      if (Call.getNumArgs() == 2) {
        verifyMatch(C, Call.getArgSVal(1),
                    InstCall->getCXXThisVal().getAsRegion());
      }
    } else if (isInsertCall(Func)) {
      verifyMatch(C, Call.getArgSVal(0),
                  InstCall->getCXXThisVal().getAsRegion());
      if (Call.getNumArgs() == 3 &&
          isIteratorType(Call.getArgExpr(1)->getType()) &&
          isIteratorType(Call.getArgExpr(2)->getType())) {
        verifyMatch(C, Call.getArgSVal(1), Call.getArgSVal(2));
      }
    } else if (isEmplaceCall(Func)) {
      verifyMatch(C, Call.getArgSVal(0),
                  InstCall->getCXXThisVal().getAsRegion());
    }
  } else if (ChecksEnabled[CK_IteratorOutOfRangeChecker] &&
             (isStdAdvanceCall(Func) || isStdNextCall(Func))) {
    verifyRandomIncrOrDecr(C, OO_Plus, Call.getArgSVal(0), Call.getArgSVal(1));
  } else if (ChecksEnabled[CK_IteratorOutOfRangeChecker] &&
             isStdPrevCall(Func)) {
    verifyRandomIncrOrDecr(C, OO_Minus, Call.getArgSVal(0), Call.getArgSVal(1));
  } else if (!isa<CXXConstructorCall>(&Call)) {
    // The main purpose of iterators is to abstract away from different
    // containers and provide a (maybe limited) uniform access to them.
    // This implies that any correctly written template function that
    // works on multiple containers using iterators takes different
    // template parameters for different containers. So we can safely
    // assume that passing iterators of different containers as arguments
    // whose type replaces the same template parameter is a bug.
    //
    // Example:
    // template<typename I1, typename I2>
    // void f(I1 first1, I1 last1, I2 first2, I2 last2);
    //
    // In this case the first two arguments to f() must be iterators must belong
    // to the same container and the last to also to the same container but
    // not neccessarily to the same as the first two.

    if (!ChecksEnabled[CK_IteratorMismatchChecker])
      return;

    const auto *Templ = Func->getPrimaryTemplate();
    if (!Templ)
      return;

    const auto *TParams = Templ->getTemplateParameters();
    const auto *TArgs = Func->getTemplateSpecializationArgs();

    for (size_t i = 0; i < TParams->size(); ++i) {
      const auto *TPDecl = dyn_cast<TemplateTypeParmDecl>(TParams->getParam(i));
      if (!TPDecl)
        continue;

      if (TPDecl->isParameterPack())
        continue;

      const auto TAType = TArgs->get(i).getAsType();
      if (!isIteratorType(TAType))
        continue;

      SVal LHS = UndefinedVal();

      // For every template parameter which is an iterator type in the
      // instantiation look for all functions parameters type by it and
      // check whether they belong to the same container
      for (auto j = 0U; j < Func->getNumParams(); ++j) {
        const auto *Param = Func->getParamDecl(j);
        const auto *ParamType =
            Param->getType()->getAs<SubstTemplateTypeParmType>();
        if (!ParamType ||
            ParamType->getReplacedParameter()->getDecl() != TPDecl)
          continue;
        if (LHS.isUndef()) {
          LHS = Call.getArgSVal(j);
        } else {
          verifyMatch(C, LHS, Call.getArgSVal(j));
        }
      }
    }
  }
}

void IteratorChecker::checkPostCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Record new iterator positions and iterator position changes
  const auto *Func = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!Func)
    return;

  if (Func->isOverloadedOperator()) {
    const auto Op = Func->getOverloadedOperator();
    if (isAssignmentOperator(Op)) {
      const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call);

      if (isIteratorType(Call.getResultType())) {
        handleIteratorAssign(C, InstCall->getCXXThisVal(), Call.getArgSVal(0),
                             Call.getReturnValue());
        return;
      }
      if (Func->getParamDecl(0)->getType()->isRValueReferenceType()) {
        handleContainerAssign(C, InstCall->getCXXThisVal(),
                              Call.getOriginExpr(), Call.getArgSVal(0));
        return;
      }

      handleContainerAssign(C, InstCall->getCXXThisVal());
      return;
    } else if (isSimpleComparisonOperator(Op)) {
      const auto *OrigExpr = Call.getOriginExpr();
      if (!OrigExpr)
        return;

      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        handleComparison(C, OrigExpr, Call.getReturnValue(),
                         InstCall->getCXXThisVal(), Call.getArgSVal(0), Op);
        return;
      } else {
        handleComparison(C, OrigExpr, Call.getReturnValue(), Call.getArgSVal(0),
                         Call.getArgSVal(1), Op);
        return;
      }
    } else if (isRandomIncrOrDecrOperator(Func->getOverloadedOperator())) {
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        if (Call.getNumArgs() >= 1 &&
            Call.getArgExpr(0)->getType()->isIntegralOrEnumerationType()) {
          handleRandomIncrOrDecr(C, Func->getOverloadedOperator(),
                                 Call.getReturnValue(),
                                 InstCall->getCXXThisVal(), Call.getArgSVal(0));
          return;
        }
      } else {
        if (Call.getNumArgs() >= 2 &&
            Call.getArgExpr(1)->getType()->isIntegralOrEnumerationType()) {
          handleRandomIncrOrDecr(C, Func->getOverloadedOperator(),
                                 Call.getReturnValue(), Call.getArgSVal(0),
                                 Call.getArgSVal(1));
          return;
        }
      }
    } else if (isIncrementOperator(Func->getOverloadedOperator())) {
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        handleIncrement(C, Call.getReturnValue(), InstCall->getCXXThisVal(),
                        Call.getNumArgs());
        return;
      } else {
        handleIncrement(C, Call.getReturnValue(), Call.getArgSVal(0),
                        Call.getNumArgs());
        return;
      }
    } else if (isDecrementOperator(Func->getOverloadedOperator())) {
      if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
        handleDecrement(C, Call.getReturnValue(), InstCall->getCXXThisVal(),
                        Call.getNumArgs());
        return;
      } else {
        handleDecrement(C, Call.getReturnValue(), Call.getArgSVal(0),
                        Call.getNumArgs());
        return;
      }
    }
  } else {
    if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
      if (isAssignCall(Func)) {
        handleContainerAssign(C, InstCall->getCXXThisVal());
        return;
      }
      if (isClearCall(Func)) {
        handleClear(C, InstCall->getCXXThisVal());
        return;
      }
      if (isPushBackCall(Func) || isEmplaceBackCall(Func)) {
        handlePushBack(C, InstCall->getCXXThisVal());
        return;
      }
      if (isPopBackCall(Func)) {
        handlePopBack(C, InstCall->getCXXThisVal());
        return;
      }
      if (isPushFrontCall(Func) || isEmplaceFrontCall(Func)) {
        handlePushFront(C, InstCall->getCXXThisVal());
        return;
      }
      if (isPopFrontCall(Func)) {
        handlePopFront(C, InstCall->getCXXThisVal());
        return;
      }
      if (isInsertCall(Func) || isEmplaceCall(Func)) {
        handleInsert(C, Call.getArgSVal(0));
        return;
      }

      if (isEraseCall(Func)) {
        if (Call.getNumArgs() == 1) {
          handleErase(C, Call.getArgSVal(0), Call.getReturnValue(),
                      Call.getOriginExpr());
          return;
        }
        if (Call.getNumArgs() == 2) {
          handleErase(C, Call.getArgSVal(0), Call.getArgSVal(1),
                      Call.getReturnValue());
          return;
        }
      }

      if (isEraseAfterCall(Func)) {
        if (Call.getNumArgs() == 1) {
          handleEraseAfter(C, Call.getArgSVal(0), Call.getReturnValue());
          return;
        }
        if (Call.getNumArgs() == 2) {
          handleEraseAfter(C, Call.getArgSVal(0), Call.getArgSVal(1),
                           Call.getReturnValue());
          return;
        }
      }
    }

    // If std::advance() (also std::__advance()), std::prev() or std::next() was
    // not inlined, that iterator position was not shifted. We have to do it
    // manually
    if (!C.wasInlined) {
      if (isStdAdvanceCall(Func)) {
        handleRandomIncrOrDecr(C, OO_PlusEqual, UndefinedVal(),
                               Call.getArgSVal(0), Call.getArgSVal(1));
        return;
      }
      if (isStdPrevCall(Func)) {
        handleRandomIncrOrDecr(C, OO_Minus, Call.getReturnValue(),
                               Call.getArgSVal(0), Call.getArgSVal(1));
        return;
      }
      if (isStdNextCall(Func)) {
        handleRandomIncrOrDecr(C, OO_Plus, Call.getReturnValue(),
                               Call.getArgSVal(0), Call.getArgSVal(1));
        return;
      }
    }

    const auto *OrigExpr = Call.getOriginExpr();
    if (!OrigExpr)
      return;

    if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
      if (isEmptyCall(Func)) {
        handleEmpty(C, OrigExpr, Call.getReturnValue(),
                    InstCall->getCXXThisVal());
      }
    }

    if (!isIteratorType(Call.getResultType()))
      return;

    auto State = C.getState();

    if (const auto *InstCall = dyn_cast<CXXInstanceCall>(&Call)) {
      auto ThisType = InstCall->getCXXThisExpr()->getType();
      if (ThisType->isPointerType()) {
        ThisType = ThisType->getPointeeType();
      }

      if (isIteratorType(ThisType)) {
        if (const auto *Pos =
                getIteratorPosition(State, InstCall->getCXXThisVal())) {
          assignToContainer(C, OrigExpr, Call.getReturnValue(),
                            Pos->getContainer());
          return;
        }
      }

      if (isContainerTypeFor(ThisType, Call.getResultType())) {
        if (isBeginCall(Func)) {
          handleBegin(C, OrigExpr, Call.getReturnValue(),
                      InstCall->getCXXThisVal());
          return;
        }
        if (isEndCall(Func)) {
          handleEnd(C, OrigExpr, Call.getReturnValue(),
                    InstCall->getCXXThisVal());
          return;
        }
        if (const auto *ThisReg = InstCall->getCXXThisVal().getAsRegion()) {
          assignToContainer(C, OrigExpr, Call.getReturnValue(), ThisReg);
          return;
        }
      }
    }

    // Already bound to container?
    if (getIteratorPosition(State, Call.getReturnValue())) {
      return;
    }

    // Copy-like and move constructors
    if (isa<CXXConstructorCall>(&Call) && Call.getNumArgs() == 1) {
      if (const auto *Pos = getIteratorPosition(State, Call.getArgSVal(0))) {
        State = setIteratorPosition(State, Call.getReturnValue(), *Pos);
        if (cast<CXXConstructorDecl>(Func)->isMoveConstructor()) {
          State = removeIteratorPosition(State, Call.getArgSVal(0));
        }
        C.addTransition(State);
        return;
      }
    }

    // Assumption: if return value is an iterator which is not yet bound to a
    //             container, then look for the first iterator argument, and
    //             bind the return value to the same container. This approach
    //             works for STL algorithms.
    // FIXME: Add a more conservative mode
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      if (Call.getArgExpr(i)->getType().getTypePtr() ==
          Call.getResultType().getTypePtr()) {
        if (const auto *Pos = getIteratorPosition(State, Call.getArgSVal(i))) {
          assignToContainer(C, OrigExpr, Call.getReturnValue(),
                            Pos->getContainer());
          return;
        }
      }
    }
  }
}

void IteratorChecker::checkPreStmt(const CXXConstructExpr *CCE,
                                   CheckerContext &C) const {
  // Check match of first-last iterator pair in a constructor of a container
  if (CCE->getNumArgs() < 2)
    return;

  const auto *Ctr = CCE->getConstructor();
  if (Ctr->getNumParams() < 2)
    return;

  if (Ctr->getParamDecl(0)->getName() != "first" ||
      Ctr->getParamDecl(1)->getName() != "last")
    return;

  if (!isIteratorType(CCE->getArg(0)->getType()) ||
      !isIteratorType(CCE->getArg(1)->getType()))
    return;

  auto State = C.getState();
  const auto *LCtx = C.getPredecessor()->getLocationContext();

  verifyMatch(C, State->getSVal(CCE->getArg(0), LCtx),
              State->getSVal(CCE->getArg(1), LCtx));
}

void IteratorChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                CheckerContext &C) const {
  auto State = C.getState();
  const auto *Pos = getIteratorPosition(State, Val);
  if (Pos) {
    State = setIteratorPosition(State, Loc, *Pos);
    C.addTransition(State);
  } else {
    const auto *OldPos = getIteratorPosition(State, Loc);
    if (OldPos) {
      State = removeIteratorPosition(State, Loc);
      C.addTransition(State);
    }
  }
}

void IteratorChecker::checkBeginFunction(CheckerContext &C) const {
  // Copy state of iterator arguments to iterator parameters
  auto State = C.getState();
  const auto *LCtx = C.getLocationContext();

  const auto *Site = cast<StackFrameContext>(LCtx)->getCallSite();
  if (!Site)
    return;

  const auto *FD = dyn_cast<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  const auto *CE = dyn_cast<CallExpr>(Site);
  const auto *CCE = dyn_cast<CXXConstructExpr>(Site);
  if (!CE && !CCE)
    return;

  bool Change = false;
  int idx = 0;
  for (const auto P : FD->parameters()) {
    auto Param = State->getLValue(P, LCtx);
    auto Arg = State->getSVal(CE ? CE->getArg(idx++) : CCE->getArg(idx++),
                              LCtx->getParent());
    const auto *Pos = getIteratorPosition(State, Arg);
    if (!Pos)
      continue;
    State = setIteratorPosition(State, Param, *Pos);
    Change = true;
  }

  if (Change) {
    C.addTransition(State);
  }
}

void IteratorChecker::checkPostStmt(const MaterializeTemporaryExpr *MTE,
                                    CheckerContext &C) const {
  /* Transfer iterator state to temporary objects */
  auto State = C.getState();
  const auto *Pos =
      getIteratorPosition(State, C.getSVal(MTE->getSubExpr()));
  if (!Pos)
    return;
  State = setIteratorPosition(State, C.getSVal(MTE), *Pos);
  C.addTransition(State);
}

void IteratorChecker::checkLiveSymbols(ProgramStateRef State,
                                       SymbolReaper &SR) const {
  // Keep symbolic expressions of iterator positions, container begins and ends
  // alive
  auto RegionMap = State->get<IteratorRegionMap>();
  for (const auto Reg : RegionMap) {
    const auto Pos = Reg.second;
    SR.markLive(Pos.getOffset());
    if (const auto *SIE = dyn_cast<SymIntExpr>(Pos.getOffset()))
      SR.markLive(SIE->getLHS());
    SR.markLive(Pos.getContainer());
  }

  auto SymbolMap = State->get<IteratorSymbolMap>();
  for (const auto Sym : SymbolMap) {
    const auto Pos = Sym.second;
    SR.markLive(Pos.getOffset());
    if (const auto *SIE = dyn_cast<SymIntExpr>(Pos.getOffset()))
      SR.markLive(SIE->getLHS());
    SR.markLive(Pos.getContainer());
  }

  auto ContMap = State->get<ContainerMap>();
  for (const auto Cont : ContMap) {
    const auto CData = Cont.second;
    if (CData.getBegin()) {
      SR.markLive(CData.getBegin());
      if (const auto *SIE = dyn_cast<SymIntExpr>(CData.getBegin()))
        SR.markLive(SIE->getLHS());
    }
    if (CData.getEnd()) {
      SR.markLive(CData.getEnd());
      if (const auto *SIE = dyn_cast<SymIntExpr>(CData.getEnd()))
        SR.markLive(SIE->getLHS());
    }
  }
}

void IteratorChecker::checkDeadSymbols(SymbolReaper &SR,
                                       CheckerContext &C) const {
  // Cleanup
  auto State = C.getState();

  auto RegionMap = State->get<IteratorRegionMap>();
  for (const auto Reg : RegionMap) {
    if (!SR.isLiveRegion(Reg.first)) {
      // FIXME: We should clean up all iterator positions whose region is dead.
      //       However, we use the region of LazyCompoundVals which may become
      //       dead before we need them. Clang 7 provides a solution to skip
      //       LazyCompoundVals completely during the construction of objects.
      //       After upgrading to Clang 7, this new method must be used and this
      //       temporary workaround removed.
      if (!Reg.second.isValid()) {
        State = State->remove<IteratorRegionMap>(Reg.first);
      }
    }
  }

  auto SymbolMap = State->get<IteratorSymbolMap>();
  for (const auto Sym : SymbolMap) {
    if (!SR.isLive(Sym.first)) {
      State = State->remove<IteratorSymbolMap>(Sym.first);
    }
  }

  auto ContMap = State->get<ContainerMap>();
  for (const auto Cont : ContMap) {
    if (!SR.isLiveRegion(Cont.first)) {
      State = State->remove<ContainerMap>(Cont.first);
    }
  }

  C.addTransition(State);
}

// FIXME: Evaluation of these STL calls should be moved to StdCLibraryFunctions
//       checker (see patch r284960) or another similar checker for C++ STL
//       functions (e.g. StdCXXLibraryFunctions or StdCppLibraryFunctions).
bool IteratorChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  const auto *CE = dyn_cast_or_null<CallExpr>(Call.getOriginExpr());
  if (!CE)
    return false;

  const FunctionDecl *FD = C.getCalleeDecl(CE);
  if (!FD)
    return false;

  ASTContext &Ctx = C.getASTContext();
  initIdentifiers(Ctx);

  if (FD->getKind() == Decl::Function) {
    if (FD->isInStdNamespace()) {
      if (FD->getIdentifier() == II_find)
        return evalFind(C, CE);
      if (FD->getIdentifier() == II_find_end)
        return evalFindEnd(C, CE);
      if (FD->getIdentifier() == II_find_first_of)
        return evalFindFirstOf(C, CE);
      if (FD->getIdentifier() == II_find_if)
        return evalFindIf(C, CE);
      if (FD->getIdentifier() == II_find_if)
        return evalFindIf(C, CE);
      if (FD->getIdentifier() == II_find_if_not)
        return evalFindIfNot(C, CE);
      if (FD->getIdentifier() == II_upper_bound)
        return evalUpperBound(C, CE);
      if (FD->getIdentifier() == II_lower_bound)
        return evalLowerBound(C, CE);
      if (FD->getIdentifier() == II_search)
        return evalSearch(C, CE);
      if (FD->getIdentifier() == II_search_n)
        return evalSearchN(C, CE);
    }
  }

  return false;
}

// This function tells the analyzer's engine that symbols produced by our
// checker, most notably iterator positions, are relatively small.
// A distance between items in the container should not be very large.
// By assuming that it is within around 1/8 of the address space,
// we can help the analyzer perform operations on these symbols
// without being afraid of integer overflows.
// FIXME: Should we provide it as an API, so that all checkers could use it?
static ProgramStateRef assumeNoOverflow(ProgramStateRef State, SymbolRef Sym,
                                        long Scale) {
  SValBuilder &SVB = State->getStateManager().getSValBuilder();
  BasicValueFactory &BV = SVB.getBasicValueFactory();

  QualType T = Sym->getType();
  assert(T->isSignedIntegerOrEnumerationType());
  APSIntType AT = BV.getAPSIntType(T);

  ProgramStateRef NewState = State;

  llvm::APSInt Max = AT.getMaxValue() / AT.getValue(Scale);
  SVal IsCappedFromAbove =
      SVB.evalBinOpNN(State, BO_LE, nonloc::SymbolVal(Sym),
                      nonloc::ConcreteInt(Max), SVB.getConditionType());
  if (auto DV = IsCappedFromAbove.getAs<DefinedSVal>()) {
    NewState = NewState->assume(*DV, true);
    if (!NewState)
      return State;
  }

  llvm::APSInt Min = -Max;
  SVal IsCappedFromBelow =
      SVB.evalBinOpNN(State, BO_GE, nonloc::SymbolVal(Sym),
                      nonloc::ConcreteInt(Min), SVB.getConditionType());
  if (auto DV = IsCappedFromBelow.getAs<DefinedSVal>()) {
    NewState = NewState->assume(*DV, true);
    if (!NewState)
      return State;
  }

  return NewState;
}

void IteratorChecker::handleComparison(CheckerContext &C, const Expr *CE,
                                       SVal RetVal, const SVal &LVal,
                                       const SVal &RVal,
                                       OverloadedOperatorKind Op) const {
  // Record the operands and the operator of the comparison for the next
  // evalAssume, if the result is a symbolic expression. If it is a concrete
  // value (only one branch is possible), then transfer the state between
  // the operands according to the operator and the result
  auto State = C.getState();
  const auto *LPos = getIteratorPosition(State, LVal);
  const auto *RPos = getIteratorPosition(State, RVal);
  const MemRegion *Cont = nullptr;
  if (LPos) {
    Cont = LPos->getContainer();
  } else if (RPos) {
    Cont = RPos->getContainer();
  }
  if (!Cont)
    return;

  // At least one of the iterators have recorded positions. If one of them has
  // not then create a new symbol for the offset.
  SymbolRef Sym;
  if (!LPos || !RPos) {
    auto &SymMgr = C.getSymbolManager();
    Sym = SymMgr.conjureSymbol(CE, C.getLocationContext(),
                               C.getASTContext().LongTy, C.blockCount());
    State = assumeNoOverflow(State, Sym, 4);
  }

  if (!LPos) {
    State = setIteratorPosition(State, LVal,
                                IteratorPosition::getPosition(Cont, Sym));
    LPos = getIteratorPosition(State, LVal);
  } else if (!RPos) {
    State = setIteratorPosition(State, RVal,
                                IteratorPosition::getPosition(Cont, Sym));
    RPos = getIteratorPosition(State, RVal);
  }

  if (!LPos || !RPos)
    return;

  if (RetVal.isUnknown()) {
    auto &SymMgr = C.getSymbolManager();
    auto *LCtx = C.getLocationContext();
    RetVal = nonloc::SymbolVal(SymMgr.conjureSymbol(
        CE, LCtx, C.getASTContext().BoolTy, C.blockCount()));
    State = State->BindExpr(CE, LCtx, RetVal);
  }

  processComparison(C, State, LPos->getOffset(), RPos->getOffset(), RetVal, Op);
}

void IteratorChecker::handleEmpty(CheckerContext &C, const Expr *CE,
                                  const SVal &RetVal, const SVal &Cont) const {
  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  // If the container already has a begin symbol then use it. Otherwise first
  // create a new one.
  auto State = C.getState();
  auto BeginSym = getContainerBegin(State, ContReg);
  if (!BeginSym) {
    State = createContainerBegin(State, ContReg, CE, C.getASTContext().LongTy,
                                 C.getLocationContext(), C.blockCount());
    BeginSym = getContainerBegin(State, ContReg);
  }
  auto EndSym = getContainerEnd(State, ContReg);
  if (!EndSym) {
    State = createContainerEnd(State, ContReg, CE, C.getASTContext().LongTy,
                               C.getLocationContext(), C.blockCount());
    EndSym = getContainerEnd(State, ContReg);
  }

  processComparison(C, State, BeginSym, EndSym, RetVal, OO_EqualEqual);
}

void IteratorChecker::processComparison(CheckerContext &C,
                                        ProgramStateRef State, SymbolRef Sym1,
                                        SymbolRef Sym2, const SVal &RetVal,
                                        OverloadedOperatorKind Op) const {
  if (const auto TruthVal = RetVal.getAs<nonloc::ConcreteInt>()) {
    if ((State = relateSymbols(State, Sym1, Sym2,
                               (Op == OO_EqualEqual) ==
                                   (TruthVal->getValue() != 0)))) {
      C.addTransition(State);
    } else {
      C.generateSink(State, C.getPredecessor());
    }
    return;
  }

  const auto ConditionVal = RetVal.getAs<DefinedSVal>();
  if (!ConditionVal)
    return;

  if (auto StateTrue = relateSymbols(State, Sym1, Sym2, Op == OO_EqualEqual)) {
    StateTrue = StateTrue->assume(*ConditionVal, true);
    C.addTransition(StateTrue);
  }

  if (auto StateFalse = relateSymbols(State, Sym1, Sym2, Op != OO_EqualEqual)) {
    StateFalse = StateFalse->assume(*ConditionVal, false);
    C.addTransition(StateFalse);
  }
}

void IteratorChecker::verifyDereference(CheckerContext &C,
                                        const SVal &Val) const {
  auto State = C.getState();
  const auto *Pos = getIteratorPosition(State, Val);
  if (Pos && isPastTheEnd(State, *Pos)) {
    auto *N = C.generateErrorNode(State);
    if (!N)
      return;
    reportOutOfRangeBug("Past-the-end iterator dereferenced.", Val, C, N, Pos);
  }
}

void IteratorChecker::verifyAccess(CheckerContext &C, const SVal &Val) const {
  auto State = C.getState();
  const auto *Pos = getIteratorPosition(State, Val);
  if (Pos && !Pos->isValid()) {
    auto *N = C.generateErrorNode(State);
    if (!N)
      return;
    reportInvalidatedBug("Invalidated iterator accessed.", Val, C, N, Pos);
  }
}

void IteratorChecker::handleIncrement(CheckerContext &C, const SVal &RetVal,
                                      const SVal &Iter, bool Postfix) const {
  // Increment the symbolic expressions which represents the position of the
  // iterator
  auto State = C.getState();
  auto &SymMgr = C.getSymbolManager();
  auto &BVF = SymMgr.getBasicVals();
  if (Postfix) {
    State = copyIteratorPosition(State, Iter, RetVal);
  }
  State =
      advancePosition(State, OO_Plus, Iter,
                      nonloc::ConcreteInt(BVF.getValue(llvm::APSInt::get(1))),
                      C.getLocationContext(), C.blockCount());
  if (!Postfix) {
    State = copyIteratorPosition(State, Iter, RetVal);
  }
  C.addTransition(State);
}

void IteratorChecker::handleDecrement(CheckerContext &C, const SVal &RetVal,
                                      const SVal &Iter, bool Postfix) const {
  // Decrement the symbolic expressions which represents the position of the
  // iterator
  auto State = C.getState();
  auto &SymMgr = C.getSymbolManager();
  auto &BVF = SymMgr.getBasicVals();
  if (Postfix) {
    State = copyIteratorPosition(State, Iter, RetVal);
  }
  State =
      advancePosition(State, OO_Minus, Iter,
                      nonloc::ConcreteInt(BVF.getValue(llvm::APSInt::get(1))),
                      C.getLocationContext(), C.blockCount());
  if (!Postfix) {
    State = copyIteratorPosition(State, Iter, RetVal);
  }
  C.addTransition(State);
}

void IteratorChecker::handleRandomIncrOrDecr(CheckerContext &C,
                                             OverloadedOperatorKind Op,
                                             const SVal &RetVal,
                                             const SVal &LHS,
                                             const SVal &RHS) const {
  // Increment or decrement the symbolic expressions which represents the
  // position of the iterator
  auto State = C.getState();

  const auto *Value = &RHS;
  SVal RawSVal;
  if (auto loc = RHS.getAs<Loc>()) {
    RawSVal = State->getRawSVal(*loc);
    Value = &RawSVal;
  }

  if (Op == OO_PlusEqual || Op == OO_MinusEqual) {
    State = advancePosition(State, Op, LHS, *Value, C.getLocationContext(),
                            C.blockCount());
  } else {
    State = copyIteratorPosition(State, LHS, RetVal);
    State = advancePosition(State, Op, RetVal, *Value, C.getLocationContext(),
                            C.blockCount());
  }
  C.addTransition(State);
}

void IteratorChecker::handleIteratorAssign(CheckerContext &C,
                                           const SVal &NewIter,
                                           const SVal &OldIter,
                                           const SVal &RetVal) const {
  auto State = C.getState();
  const auto *Pos = getIteratorPosition(State, OldIter);
  if (!Pos)
    return;

  State = setIteratorPosition(State, NewIter, *Pos);
  if (RetVal != OldIter) {
    State = setIteratorPosition(State, RetVal, *Pos);
  }
  C.addTransition(State);
}

void IteratorChecker::verifyIncrement(CheckerContext &C,
                                      const SVal &Iter) const {
  verifyRandomIncrOrDecr(C, OO_Plus, Iter,
                         CI_ONE(C.getSValBuilder().getBasicValueFactory()));
}

void IteratorChecker::verifyDecrement(CheckerContext &C,
                                      const SVal &Iter) const {
  verifyRandomIncrOrDecr(C, OO_Minus, Iter,
                         CI_ONE(C.getSValBuilder().getBasicValueFactory()));
}

void IteratorChecker::verifyRandomIncrOrDecr(CheckerContext &C,
                                             OverloadedOperatorKind Op,
                                             const SVal &LHS,
                                             const SVal &RHS) const {
  auto State = C.getState();

  // If the iterator is initially inside its range, then the operation is valid
  const auto *Pos = getIteratorPosition(State, LHS);
  if (!Pos)
    return;

  auto Value = RHS;
  if (auto ValAsLoc = RHS.getAs<Loc>()) {
    Value = State->getRawSVal(*ValAsLoc);
  }

  if (Value.isUnknown())
    return;

  // Incremention or decremention by 0 is never bug
  if (State->isNull(Value).isConstrainedTrue())
    return;

  // The result may be the past-end iterator of the container, but any other
  // out of range position is undefined behaviour
  const auto NewState = advancePosition(State, Op, LHS, Value,
                                        C.getLocationContext(), C.blockCount());
  Pos = getIteratorPosition(NewState, LHS);

  if (isAheadOfRange(NewState, *Pos)) {
    auto *N = C.generateNonFatalErrorNode(State);
    if (!N)
      return;
    reportOutOfRangeBug("Iterator decremented ahead of its valid range.", LHS,
                        C, N, Pos, false);
  }
  if (isBehindPastTheEnd(NewState, *Pos)) {
    auto *N = C.generateNonFatalErrorNode(State);
    if (!N)
      return;
    reportOutOfRangeBug("Iterator incremented behind the past-the-end "
                        "iterator.",
                        LHS, C, N, Pos);
  }
}

void IteratorChecker::verifyMatch(CheckerContext &C, const SVal &Iter,
                                  const MemRegion *Cont) const {
  // Verify match between a container and the container of an iterator
  Cont = getTopRegion(Cont);

  if (isa<CXXTempObjectRegion>(Cont))
    return;
  if (const auto *ContSym = Cont->getSymbolicBase()) {
    if (isa<SymbolConjured>(ContSym->getSymbol()))
      return;
  }

  auto State = C.getState();
  const auto *Pos = getIteratorPosition(State, Iter);
  if (!Pos)
    return;

  const auto *IterCont = Pos->getContainer();
  if (isa<CXXTempObjectRegion>(IterCont))
    return;
  if (const auto *ContSym = IterCont->getSymbolicBase()) {
    if (isa<SymbolConjured>(ContSym->getSymbol()))
      return;
  }

  if (IterCont != Cont) {
    auto *N = C.generateNonFatalErrorNode(State);
    if (!N) {
      return;
    }
    reportMismatchedBug("Container accessed using foreign iterator argument.",
                        Iter, Cont, C, N);
  }
}

void IteratorChecker::verifyMatch(CheckerContext &C, const SVal &Iter1,
                                  const SVal &Iter2) const {
  // Verify match between the containers of two iterators
  auto State = C.getState();
  const auto *Pos1 = getIteratorPosition(State, Iter1);
  if (!Pos1)
    return;

  const auto *IterCont1 = Pos1->getContainer();
  if (isa<CXXTempObjectRegion>(IterCont1))
    return;
  if (const auto *ContSym = IterCont1->getSymbolicBase()) {
    if (isa<SymbolConjured>(ContSym->getSymbol()))
      return;
  }

  const auto *Pos2 = getIteratorPosition(State, Iter2);
  if (!Pos2)
    return;

  const auto *IterCont2 = Pos2->getContainer();
  if (isa<CXXTempObjectRegion>(IterCont2))
    return;
  if (const auto *ContSym = IterCont2->getSymbolicBase()) {
    if (isa<SymbolConjured>(ContSym->getSymbol()))
      return;
  }

  if (IterCont1 != IterCont2) {
    auto *N = C.generateNonFatalErrorNode(State);
    if (!N) {
      return;
    }
    reportMismatchedBug("Iterators of different containers used where the "
                        "same container is expected.",
                        Iter1, Iter2, C, N);
  }
}

void IteratorChecker::handleBegin(CheckerContext &C, const Expr *CE,
                                  const SVal &RetVal, const SVal &Cont) const {
  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  // If the container already has a begin symbol then use it. Otherwise first
  // create a new one.
  auto State = C.getState();
  auto BeginSym = getContainerBegin(State, ContReg);
  if (!BeginSym) {
    State = createContainerBegin(State, ContReg, CE, C.getASTContext().LongTy,
                                 C.getLocationContext(), C.blockCount());
    BeginSym = getContainerBegin(State, ContReg);
  }
  State = setIteratorPosition(State, RetVal,
                              IteratorPosition::getPosition(ContReg, BeginSym));
  C.addTransition(State);
}

void IteratorChecker::handleEnd(CheckerContext &C, const Expr *CE,
                                const SVal &RetVal, const SVal &Cont) const {
  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  // If the container already has an end symbol then use it. Otherwise first
  // create a new one.
  auto State = C.getState();
  auto EndSym = getContainerEnd(State, ContReg);
  if (!EndSym) {
    State = createContainerEnd(State, ContReg, CE, C.getASTContext().LongTy,
                               C.getLocationContext(), C.blockCount());
    EndSym = getContainerEnd(State, ContReg);
  }
  State = setIteratorPosition(State, RetVal,
                              IteratorPosition::getPosition(ContReg, EndSym));
  C.addTransition(State);
}

void IteratorChecker::assignToContainer(CheckerContext &C, const Expr *CE,
                                        const SVal &RetVal,
                                        const MemRegion *Cont) const {
  Cont = getTopRegion(Cont);

  auto State = C.getState();
  auto &SymMgr = C.getSymbolManager();
  auto Sym = SymMgr.conjureSymbol(CE, C.getLocationContext(),
                                  C.getASTContext().LongTy, C.blockCount());
  State = assumeNoOverflow(State, Sym, 4);
  State = setIteratorPosition(State, RetVal,
                              IteratorPosition::getPosition(Cont, Sym));
  C.addTransition(State);
}

void IteratorChecker::handleContainerAssign(CheckerContext &C, const SVal &Cont,
                                            const Expr *CE,
                                            const SVal &OldCont) const {
  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  // Assignment of a new value to a container always invalidates all its
  // iterators
  auto State = C.getState();
  const auto CData = getContainerData(State, ContReg);
  if (CData) {
    State = invalidateAllIteratorPositions(State, ContReg);
  }

  // In case of move, iterators of the old container (except the past-end
  // iterators) remain valid but refer to the new container
  if (!OldCont.isUndef()) {
    const auto *OldContReg = OldCont.getAsRegion();
    if (OldContReg) {
      OldContReg = getTopRegion(OldContReg);
      const auto OldCData = getContainerData(State, OldContReg);
      if (OldCData) {
        if (const auto OldEndSym = OldCData->getEnd()) {
          // If we already assigned an "end" symbol to the old conainer, then
          // first reassign all iterator positions to the new container which
          // are not past the container (thus not greater or equal to the
          // current "end" symbol.
          State = reassignAllIteratorPositionsUnless(State, OldContReg, ContReg,
                                                     OldEndSym, BO_GE);
          auto &SymMgr = C.getSymbolManager();
          auto &SVB = C.getSValBuilder();
          auto NewEndSym =
              SymMgr.conjureSymbol(CE, C.getLocationContext(),
                                   C.getASTContext().LongTy, C.blockCount());
          State = assumeNoOverflow(State, NewEndSym, 4);
          if (CData) {
            State = setContainerData(State, ContReg, CData->newEnd(NewEndSym));
          } else {
            State = setContainerData(State, ContReg,
                                     ContainerData::fromEnd(NewEndSym));
          }
          State = rebaseSymbolInIteratorPositionsIf(
              State, SVB, OldEndSym, NewEndSym, OldEndSym, BO_LT);
        } else {
          State = reassignAllIteratorPositions(State, OldContReg, ContReg);
        }
        if (const auto OldBeginSym = OldCData->getBegin()) {
          if (CData) {
            State =
                setContainerData(State, ContReg, CData->newBegin(OldBeginSym));
          } else {
            State = setContainerData(State, ContReg,
                                     ContainerData::fromBegin(OldBeginSym));
          }
          State =
              setContainerData(State, OldContReg, OldCData->newEnd(nullptr));
        }
      } else {
        // There was neither "begin" nor "end" symbol assigned yet to the old
        // container, so reassign all iterator positions to the new container.
        State = reassignAllIteratorPositions(State, OldContReg, ContReg);
      }
    }
  }
  C.addTransition(State);
}

void IteratorChecker::handleClear(CheckerContext &C, const SVal &Cont) const {
  // TODO: ensure begin == end

  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  // The clear() operation invalidates all the iterators, except the past-end
  // iterators of list-like containers
  auto State = C.getState();
  if (!hasSubscriptOperator(ContReg) || !backModifiable(ContReg)) {
    const auto CData = getContainerData(State, ContReg);
    if (CData) {
      if (const auto EndSym = CData->getEnd()) {
        State =
            invalidateAllIteratorPositionsExcept(State, ContReg, EndSym, BO_GE);
        C.addTransition(State);
        return;
      }
    }
  }
  State = invalidateAllIteratorPositions(State, ContReg);
  C.addTransition(State);
}

void IteratorChecker::handlePushBack(CheckerContext &C,
                                     const SVal &Cont) const {
  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  // For deque-like containers invalidate all iterator positions
  auto State = C.getState();
  if (hasSubscriptOperator(ContReg) && frontModifiable(ContReg)) {
    State = invalidateAllIteratorPositions(State, ContReg);
    C.addTransition(State);
    return;
  }

  const auto CData = getContainerData(State, ContReg);
  if (!CData)
    return;

  // For vector-like containers invalidate the past-end iterator positions
  if (const auto EndSym = CData->getEnd()) {
    if (hasSubscriptOperator(ContReg)) {
      State = invalidateIteratorPositions(State, EndSym, BO_GE);
    }
    auto &SymMgr = C.getSymbolManager();
    auto &BVF = SymMgr.getBasicVals();
    auto &SVB = C.getSValBuilder();
    const auto newEndSym =
        SVB.evalBinOp(State, BO_Add, nonloc::SymbolVal(EndSym), CI_ONE(BVF),
                      SymMgr.getType(EndSym))
            .getAsSymbol();
    State = setContainerData(State, ContReg, CData->newEnd(newEndSym));
  }
  C.addTransition(State);
}

void IteratorChecker::handlePopBack(CheckerContext &C, const SVal &Cont) const {
  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  auto State = C.getState();
  const auto CData = getContainerData(State, ContReg);
  if (!CData)
    return;

  if (const auto EndSym = CData->getEnd()) {
    auto &SymMgr = C.getSymbolManager();
    auto &BVF = SymMgr.getBasicVals();
    auto &SVB = C.getSValBuilder();
    const auto BackSym = SVB.evalBinOp(State, BO_Sub, nonloc::SymbolVal(EndSym),
                                       CI_ONE(BVF), SymMgr.getType(EndSym))
                             .getAsSymbol();
    // For vector-like and deque-like containers invalidate the last and the
    // past-end iterator positions. For list-like containers only invalidate
    // the last position
    if (hasSubscriptOperator(ContReg) && backModifiable(ContReg)) {
      State = invalidateIteratorPositions(State, BackSym, BO_GE);
      State = setContainerData(State, ContReg, CData->newEnd(nullptr));
    } else {
      State = invalidateIteratorPositions(State, BackSym, BO_EQ);
    }
    auto newEndSym = BackSym;
    State = setContainerData(State, ContReg, CData->newEnd(newEndSym));
    C.addTransition(State);
  }
}

void IteratorChecker::handlePushFront(CheckerContext &C,
                                      const SVal &Cont) const {
  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  // For deque-like containers invalidate all iterator positions
  auto State = C.getState();
  if (hasSubscriptOperator(ContReg)) {
    State = invalidateAllIteratorPositions(State, ContReg);
    C.addTransition(State);
  } else {
    const auto CData = getContainerData(State, ContReg);
    if (!CData)
      return;

    if (const auto BeginSym = CData->getBegin()) {
      auto &SymMgr = C.getSymbolManager();
      auto &BVF = SymMgr.getBasicVals();
      auto &SVB = C.getSValBuilder();
      const auto newBeginSym =
          SVB.evalBinOp(State, BO_Sub, nonloc::SymbolVal(BeginSym), CI_ONE(BVF),
                        SymMgr.getType(BeginSym))
              .getAsSymbol();
      State = setContainerData(State, ContReg, CData->newBegin(newBeginSym));
      C.addTransition(State);
    }
  }
}

void IteratorChecker::handlePopFront(CheckerContext &C,
                                     const SVal &Cont) const {
  const auto *ContReg = Cont.getAsRegion();
  if (!ContReg)
    return;

  ContReg = getTopRegion(ContReg);

  auto State = C.getState();
  const auto CData = getContainerData(State, ContReg);
  if (!CData)
    return;

  // For deque-like containers invalidate all iterator positions. For list-like
  // iterators only invalidate the first position
  if (const auto BeginSym = CData->getBegin()) {
    if (hasSubscriptOperator(ContReg)) {
      State = invalidateIteratorPositions(State, BeginSym, BO_LE);
    } else {
      State = invalidateIteratorPositions(State, BeginSym, BO_EQ);
    }
    auto &SymMgr = C.getSymbolManager();
    auto &BVF = SymMgr.getBasicVals();
    auto &SVB = C.getSValBuilder();
    const auto newBeginSym =
        SVB.evalBinOp(State, BO_Add, nonloc::SymbolVal(BeginSym), CI_ONE(BVF),
                      SymMgr.getType(BeginSym))
            .getAsSymbol();
    State = setContainerData(State, ContReg, CData->newBegin(newBeginSym));
    C.addTransition(State);
  }
}

void IteratorChecker::handleInsert(CheckerContext &C, const SVal &Iter) const {
  // FIXME: increase end or decrease begin of container, adjust other iterators
  // FIXME: handle return value (new parameter)

  auto State = C.getState();
  const auto *Pos = getIteratorPosition(State, Iter);
  if (!Pos)
    return;

  // For deque-like containers invalidate all iterator positions. For
  // vector-like containers invalidate iterator positions at and after the
  // insertion.
  const auto *Cont = Pos->getContainer();
  if (hasSubscriptOperator(Cont) && backModifiable(Cont)) {
    if (frontModifiable(Cont)) {
      State = invalidateAllIteratorPositions(State, Cont);
    } else {
      State = invalidateIteratorPositions(State, Pos->getOffset(), BO_GE);
    }
    if (const auto *CData = getContainerData(State, Cont)) {
      if (const auto EndSym = CData->getEnd()) {
        State = invalidateIteratorPositions(State, EndSym, BO_GE);
        State = setContainerData(State, Cont, CData->newEnd(nullptr));
      }
    }
    C.addTransition(State);
  }
}

void IteratorChecker::handleErase(CheckerContext &C, const SVal &Iter,
                                  const SVal &RetVal, const Expr *CE) const {
  // FIXME: decrease end or increase begin of container, adjust other iterators

  auto State = C.getState();
  const auto *Pos = getIteratorPosition(State, Iter);
  if (!Pos)
    return;

  // For deque-like containers invalidate all iterator positions. For
  // vector-like containers invalidate iterator positions at and after the
  // deletion. For list-like containers only invalidate the deleted position.
  const auto *Cont = Pos->getContainer();
  if (hasSubscriptOperator(Cont) && backModifiable(Cont)) {
    if (frontModifiable(Cont)) {
      State = invalidateAllIteratorPositions(State, Cont);
    } else {
      State = invalidateIteratorPositions(State, Pos->getOffset(), BO_GE);
    }
    if (const auto *CData = getContainerData(State, Cont)) {
      if (const auto EndSym = CData->getEnd()) {
        State = invalidateIteratorPositions(State, EndSym, BO_GE);
        State = setContainerData(State, Cont, CData->newEnd(nullptr));
      }
    }
  } else {
    State = invalidateIteratorPositions(State, Pos->getOffset(), BO_EQ);
  }

  // Set the return value
  auto &SymMgr = C.getSymbolManager();
  auto &BVF = SymMgr.getBasicVals();
  auto &SVB = C.getSValBuilder();
  const auto retOffset =
      SVB.evalBinOp(State, BO_Add, nonloc::SymbolVal(Pos->getOffset()),
                    CI_ONE(BVF), SymMgr.getType(Pos->getOffset()))
          .getAsSymbol();
  auto retPos = IteratorPosition::getPosition(Pos->getContainer(), retOffset);
  State = setIteratorPosition(State, RetVal, retPos);

  if (AggressiveEraseModeling) {
    SymbolRef EndSym = getContainerEnd(State, Cont);
    // For std::vector and std::queue-like containers we just removed the
    // end symbol from the container data because the  past-the-end iterator
    // was also invalidated. The next call to member function `end()` would
    // create a new one, but we need it now so we create it now.
    if (!EndSym) {
      State = createContainerEnd(State, Cont, CE, C.getASTContext().LongTy,
                                 C.getLocationContext(), C.blockCount());
      EndSym = getContainerEnd(State, Cont);
    }
    const auto retEnd =
      SVB.evalBinOp(State, BO_EQ, nonloc::SymbolVal(retOffset),
                    nonloc::SymbolVal(EndSym), SVB.getConditionType())
      .getAs<DefinedOrUnknownSVal>();
    if (retEnd) {
      ProgramStateRef StateEnd, StateNotEnd;
      std::tie(StateEnd, StateNotEnd) = State->assume(*retEnd);
      if (StateEnd) {
        C.addTransition(StateEnd);
      }
      if (StateNotEnd) {
        C.addTransition(StateNotEnd);
      }
      return;
    }
  }

  C.addTransition(State);
}

void IteratorChecker::handleErase(CheckerContext &C, const SVal &Iter1,
                                  const SVal &Iter2, const SVal &RetVal) const {
  auto State = C.getState();
  const auto *Pos1 = getIteratorPosition(State, Iter1);
  const auto *Pos2 = getIteratorPosition(State, Iter2);
  if (!Pos1 || !Pos2)
    return;

  // For deque-like containers invalidate all iterator positions. For
  // vector-like containers invalidate iterator positions at and after the
  // deletion range. For list-like containers only invalidate the deleted
  // position range [first..last].
  const auto *Cont = Pos1->getContainer();
  if (hasSubscriptOperator(Cont) && backModifiable(Cont)) {
    if (frontModifiable(Cont)) {
      State = invalidateAllIteratorPositions(State, Cont);
    } else {
      State = invalidateIteratorPositions(State, Pos1->getOffset(), BO_GE);
    }
    if (const auto *CData = getContainerData(State, Cont)) {
      if (const auto EndSym = CData->getEnd()) {
        State = invalidateIteratorPositions(State, EndSym, BO_GE);
        State = setContainerData(State, Cont, CData->newEnd(nullptr));
      }
    }
  } else {
    State = invalidateIteratorPositions(State, Pos1->getOffset(), BO_GE,
                                        Pos2->getOffset(), BO_LT);
  }

  // Set the return value
  auto retPos =
      IteratorPosition::getPosition(Pos2->getContainer(), Pos2->getOffset());
  State = setIteratorPosition(State, RetVal, retPos);

  C.addTransition(State);
}

void IteratorChecker::handleEraseAfter(CheckerContext &C, const SVal &Iter,
                                       const SVal &RetVal) const {
  auto State = C.getState();
  const auto *Pos = getIteratorPosition(State, Iter);
  if (!Pos)
    return;

  // Invalidate the deleted iterator position, which is the position of the
  // parameter plus one.
  auto &SymMgr = C.getSymbolManager();
  auto &BVF = SymMgr.getBasicVals();
  auto &SVB = C.getSValBuilder();
  const auto NextSym =
      SVB.evalBinOp(State, BO_Add, nonloc::SymbolVal(Pos->getOffset()),
                    CI_ONE(BVF), SymMgr.getType(Pos->getOffset()))
          .getAsSymbol();
  State = invalidateIteratorPositions(State, NextSym, BO_EQ);

  // Set the return value
  const auto retOffset =
      SVB.evalBinOp(State, BO_Add, nonloc::SymbolVal(Pos->getOffset()),
                    CI_ONE(BVF), SymMgr.getType(Pos->getOffset()))
          .getAsSymbol();
  auto retPos = IteratorPosition::getPosition(Pos->getContainer(), retOffset);
  State = setIteratorPosition(State, RetVal, retPos);

  C.addTransition(State);
}

void IteratorChecker::handleEraseAfter(CheckerContext &C, const SVal &Iter1,
                                       const SVal &Iter2,
                                       const SVal &RetVal) const {
  auto State = C.getState();
  const auto *Pos1 = getIteratorPosition(State, Iter1);
  const auto *Pos2 = getIteratorPosition(State, Iter2);
  if (!Pos1 || !Pos2)
    return;

  // Invalidate the deleted iterator position range (first..last)
  State = invalidateIteratorPositions(State, Pos1->getOffset(), BO_GT,
                                      Pos2->getOffset(), BO_LT);

  // Set the return value
  State = setIteratorPosition(State, RetVal, *Pos2);

  C.addTransition(State);
}

bool IteratorChecker::evalFind(CheckerContext &C, const CallExpr *CE) const {
  if (CE->getNumArgs() == 3 && isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

bool IteratorChecker::evalFindEnd(CheckerContext &C, const CallExpr *CE) const {
  if ((CE->getNumArgs() == 4 || CE->getNumArgs() == 5) &&
      isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType()) &&
      isIteratorType(CE->getArg(2)->getType()) &&
      isIteratorType(CE->getArg(3)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

bool IteratorChecker::evalFindFirstOf(CheckerContext &C,
                                      const CallExpr *CE) const {
  if ((CE->getNumArgs() == 4 || CE->getNumArgs() == 5) &&
      isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType()) &&
      isIteratorType(CE->getArg(2)->getType()) &&
      isIteratorType(CE->getArg(3)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

bool IteratorChecker::evalFindIf(CheckerContext &C, const CallExpr *CE) const {
  if (CE->getNumArgs() == 3 && isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

bool IteratorChecker::evalFindIfNot(CheckerContext &C,
                                    const CallExpr *CE) const {
  if (CE->getNumArgs() == 3 && isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

bool IteratorChecker::evalLowerBound(CheckerContext &C,
                                     const CallExpr *CE) const {
  if ((CE->getNumArgs() == 3 || CE->getNumArgs() == 4) &&
      isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

bool IteratorChecker::evalUpperBound(CheckerContext &C,
                                     const CallExpr *CE) const {
  if ((CE->getNumArgs() == 3 || CE->getNumArgs() == 4) &&
      isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

bool IteratorChecker::evalSearch(CheckerContext &C, const CallExpr *CE) const {
  if ((CE->getNumArgs() == 4 || CE->getNumArgs() == 5) &&
      isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType()) &&
      isIteratorType(CE->getArg(2)->getType()) &&
      isIteratorType(CE->getArg(3)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

bool IteratorChecker::evalSearchN(CheckerContext &C, const CallExpr *CE) const {
  if ((CE->getNumArgs() == 4 || CE->getNumArgs() == 5) &&
      isIteratorType(CE->getArg(0)->getType()) &&
      isIteratorType(CE->getArg(1)->getType())) {
    Find(C, CE);
    return true;
  }
  return false;
}

void IteratorChecker::Find(CheckerContext &C, const CallExpr *CE) const {
  auto state = C.getState();
  auto &svalBuilder = C.getSValBuilder();
  const auto *LCtx = C.getLocationContext();

  auto RetVal = svalBuilder.conjureSymbolVal(nullptr, CE, LCtx, C.blockCount());
  auto SecondParam = state->getSVal(CE->getArg(1), LCtx);

  auto stateFound = state->BindExpr(CE, LCtx, RetVal);
  auto stateNotFound = state->BindExpr(CE, LCtx, SecondParam);

  C.addTransition(stateFound);
  C.addTransition(stateNotFound);
}

ProgramStateRef IteratorChecker::advancePosition(ProgramStateRef State,
                                                 OverloadedOperatorKind Op,
                                                 const SVal &Iter,
                                                 const SVal &Distance,
                                                 const LocationContext *LCtx,
                                                 unsigned BlockCount) const {
  const auto *Pos = getIteratorPosition(State, Iter);
  if (!Pos)
    return State;

  auto &SymMgr = State->getSymbolManager();
  auto &SVB = State->getStateManager().getSValBuilder();
  auto BinOp = (Op == OO_Plus || Op == OO_PlusEqual) ? BO_Add : BO_Sub;
  SymbolRef NewPosSym;
  if (const auto IntDist = Distance.getAs<nonloc::ConcreteInt>()) {
    // For concrete integers we can calculate the new position
    NewPosSym = SVB.evalBinOp(State, BinOp, nonloc::SymbolVal(Pos->getOffset()),
                              *IntDist, SymMgr.getType(Pos->getOffset()))
                    .getAsSymbol();
  } else {
    // For other symbols create a new symbol to keep expressions simple
    NewPosSym = SymMgr.conjureSymbol(
        nullptr, LCtx, SymMgr.getType(Pos->getOffset()), BlockCount);
    State = assumeNoOverflow(State, NewPosSym, 4);
  }

  return setIteratorPosition(State, Iter, Pos->setTo(NewPosSym));
}

void IteratorChecker::reportOutOfRangeBug(const StringRef &Message,
                                          const SVal &Val, CheckerContext &C,
                                          ExplodedNode *ErrNode,
                                          const IteratorPosition *Pos,
                                          bool PastTheEnd) const {
  if (!OutOfRangeBugType) {
    OutOfRangeBugType.reset(
      new BugType(CheckNames[CK_IteratorOutOfRangeChecker],
                  "Iterator out of range",
                  "Misuse of STL APIs"));
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*OutOfRangeBugType, Message,
                                                    ErrNode);
  R->markInteresting(Val);
  R->addVisitor(std::make_unique<IteratorBRVisitor>(
      Val, Pos->getContainer(),
      PastTheEnd ? IteratorBRVisitor::PastTheEnd
                 : IteratorBRVisitor::AheadOfRange));
  C.emitReport(std::move(R));
}

void IteratorChecker::reportMismatchedBug(const StringRef &Message,
                                          const SVal &Val1, const SVal &Val2,
                                          CheckerContext &C,
                                          ExplodedNode *ErrNode) const {
  if (!MismatchedBugType) {
    MismatchedBugType.reset(new BugType(CheckNames[CK_IteratorMismatchChecker],
                                        "Iterator(s) mismatched",
                                        "Misuse of STL APIs",
                                        /*SuppressOnSink=*/true));
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*MismatchedBugType, Message,
                                                    ErrNode);
  R->markInteresting(Val1);
  R->markInteresting(Val2);
  C.emitReport(std::move(R));
}

void IteratorChecker::reportMismatchedBug(const StringRef &Message,
                                          const SVal &Val, const MemRegion *Reg,
                                          CheckerContext &C,
                                          ExplodedNode *ErrNode) const {
  if (!MismatchedBugType) {
    MismatchedBugType.reset(new BugType(CheckNames[CK_IteratorMismatchChecker],
                                        "Iterator(s) mismatched",
                                        "Misuse of STL APIs",
                                        /*SuppressOnSink=*/true));
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*MismatchedBugType, Message,
                                                    ErrNode);
  R->markInteresting(Val);
  R->markInteresting(Reg);
  C.emitReport(std::move(R));
}

void IteratorChecker::reportInvalidatedBug(const StringRef &Message,
                                           const SVal &Val, CheckerContext &C,
                                           ExplodedNode *ErrNode,
                                           const IteratorPosition *Pos) const {
  if (!InvalidatedBugType) {
    InvalidatedBugType.reset(
      new BugType(CheckNames[CK_InvalidatedIteratorAccessChecker],
                  "Iterator invalidated", "Misuse of STL APIs"));
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*InvalidatedBugType,
                                                    Message, ErrNode);
  R->markInteresting(Val);
  R->addVisitor(std::make_unique<IteratorBRVisitor>(
      Val, Pos->getContainer(), IteratorBRVisitor::Invalidated));
  C.emitReport(std::move(R));
}

void IteratorChecker::initIdentifiers(ASTContext &Ctx) const {
  INIT_ID(find);
  INIT_ID(find_end);
  INIT_ID(find_first_of);
  INIT_ID(find_if);
  INIT_ID(find_if_not);
  INIT_ID(lower_bound);
  INIT_ID(upper_bound);
  INIT_ID(search);
  INIT_ID(search_n);
}

PathDiagnosticPieceRef
IteratorBRVisitor::VisitNode(const ExplodedNode *Succ, BugReporterContext &BRC,
                             PathSensitiveBugReport &BR) {
  if (FoundChange && FoundEmptiness)
    return nullptr;

  const ExplodedNode *Pred = Succ->getFirstPred();
  const Stmt *S = nullptr;
  const auto SP = Succ->getLocation().getAs<StmtPoint>();
  if (SP.hasValue()) {
    S = SP->getStmt();
  } else {
    const auto E = Succ->getLocation().getAs<BlockEdge>();
    if (E.hasValue()) {
      S = E->getSrc()->getTerminator().getStmt();
    }
  }

  if (!S)
    return nullptr;

  const auto &StateBefore = Pred->getState();
  const auto &StateAfter = Succ->getState();
  const auto *CDBefore = getContainerData(StateBefore, Cont);
  const auto *CDAfter = getContainerData(StateAfter, Cont);

  SmallString<256> Buf;
  llvm::raw_svector_ostream Out(Buf);

  if (!FoundChange) {
    const auto *PosBefore = getIteratorPosition(StateBefore, Iter);
    const auto *PosAfter = getIteratorPosition(StateAfter, Iter);

    // If the bug type is decremention of the iterator ahead of its range,
    // then we must find a program state pair where in the predecessor we
    // either do not store anything about the iterator or the container or
    // the iterator does not reference to the first position of the container,
    // while in the successor we store both the position of the iterator and
    // the boundaries of its container and the iterator references to the
    // first position of the container.
    if (ErrorType == AheadOfRange &&
        ((!PosBefore || !CDBefore ||
          PosBefore->getOffset() != CDBefore->getBegin()) &&
         (PosAfter && CDAfter &&
          PosAfter->getOffset() == CDAfter->getBegin()))) {
      Out << "Iterator reached the first position of the container.";
      FoundChange = true;

      // If the bug type is dereference or incremention of the past-the-end
      // iterator, then we must find a program state pair where in the
      // predecessor we either do not store anything about the iterator or the
      // container or the iterator does not reference to the past-the-end
      // of the container, while in the successor we store both the position
      // of the iterator and the boundaries of its container and the iterator
      // references to the past-the-end iterator of the container.
    } else if (ErrorType == PastTheEnd &&
               ((!PosBefore || !CDBefore ||
                 PosBefore->getOffset() != CDBefore->getEnd()) &&
                (PosAfter && CDAfter &&
                 PosAfter->getOffset() == CDAfter->getEnd()))) {
      Out << "Iterator reached the past-the-end position of the "
             "container.";
      FoundChange = true;

      // If the bug type is access of an invalidated iterator, then we must find
      // a program state pair where in the predecessor we either do not store
      // anything about the iterator or the iterator is valid, while in the
      // successor we store the position of the iterator and it is invalidated.
    } else if (ErrorType == Invalidated &&
               ((!PosBefore || PosBefore->isValid()) &&
                (PosAfter && !PosAfter->isValid()))) {
      Out << "Iterator invalidated.";
      FoundChange = true;
    }
  }

  if (!FoundEmptiness) {
    ProgramStateRef NotEmptyBefore =
        (CDBefore && CDBefore->getBegin() && CDBefore->getEnd())
            ? relateSymbols(StateBefore, CDBefore->getBegin(),
                            CDBefore->getEnd(), false)
            : StateBefore;
    ProgramStateRef NotEmptyAfter =
        (CDAfter && CDAfter->getBegin() && CDAfter->getEnd())
            ? relateSymbols(StateAfter, CDAfter->getBegin(), CDAfter->getEnd(),
                            false)
            : StateAfter;
    ProgramStateRef EmptyBefore =
        (CDBefore && CDBefore->getBegin() && CDBefore->getEnd())
            ? relateSymbols(StateBefore, CDBefore->getBegin(),
                            CDBefore->getEnd(), true)
            : StateBefore;
    ProgramStateRef EmptyAfter =
        (CDAfter && CDAfter->getBegin() && CDAfter->getEnd())
            ? relateSymbols(StateAfter, CDAfter->getBegin(), CDAfter->getEnd(),
                            true)
            : StateAfter;

    // If the container could be empty in the predecessor state and in the
    // successor state it can be non-empty and cannot be empty, then we found
    // the first program point where we assume it is non-empty.
    if (EmptyBefore && (NotEmptyAfter && !EmptyAfter)) {
      Out << "Assuming the container/range is non-empty.";
      FoundEmptiness = true;

      // If the container could be non-empty in the predecessor state and in the
      // successor state it can be empty and cannot be non-empty, then we found
      // the first program point where we assume it is empty.
    } else if (NotEmptyBefore && (EmptyAfter && !NotEmptyAfter)) {
      Out << "Assuming the container/range is empty.";
      FoundEmptiness = true;
    }
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

namespace {

bool isLess(ProgramStateRef State, SymbolRef Sym1, SymbolRef Sym2);
bool isGreater(ProgramStateRef State, SymbolRef Sym1, SymbolRef Sym2);
bool isEqual(ProgramStateRef State, SymbolRef Sym1, SymbolRef Sym2);
bool compare(ProgramStateRef State, SymbolRef Sym1, SymbolRef Sym2,
             BinaryOperator::Opcode Opc);
bool compare(ProgramStateRef State, NonLoc NL1, NonLoc NL2,
             BinaryOperator::Opcode Opc);
const CXXRecordDecl *getCXXRecordDecl(const MemRegion *Reg);
SymbolRef rebaseSymbol(ProgramStateRef State, SValBuilder &SVB, SymbolRef Expr,
                       SymbolRef OldSym, SymbolRef NewSym);
ProgramStateRef ensureNonNegativeDiff(ProgramStateRef State, SymbolRef Sym1,
                                      SymbolRef Sym2);

bool isIteratorType(const QualType &Type) {
  if (Type->isPointerType())
    return true;

  const auto *CRD = Type->getUnqualifiedDesugaredType()->getAsCXXRecordDecl();
  return isIterator(CRD);
}

bool isIterator(const CXXRecordDecl *CRD) {
  if (!CRD)
    return false;

  const auto Name = CRD->getName();
  if (!(Name.endswith_lower("iterator") || Name.endswith_lower("iter") ||
        Name.endswith_lower("it")))
    return false;

  bool HasCopyCtor = false, HasCopyAssign = true, HasDtor = false,
       HasPreIncrOp = false, HasPostIncrOp = false, HasDerefOp = false;
  for (const auto *Method : CRD->methods()) {
    if (const auto *Ctor = dyn_cast<CXXConstructorDecl>(Method)) {
      if (Ctor->isCopyConstructor()) {
        HasCopyCtor = !Ctor->isDeleted() && Ctor->getAccess() == AS_public;
      }
      continue;
    }
    if (const auto *Dtor = dyn_cast<CXXDestructorDecl>(Method)) {
      HasDtor = !Dtor->isDeleted() && Dtor->getAccess() == AS_public;
      continue;
    }
    if (Method->isCopyAssignmentOperator()) {
      HasCopyAssign = !Method->isDeleted() && Method->getAccess() == AS_public;
      continue;
    }
    if (!Method->isOverloadedOperator())
      continue;
    const auto OPK = Method->getOverloadedOperator();
    if (OPK == OO_PlusPlus) {
      HasPreIncrOp = HasPreIncrOp || (Method->getNumParams() == 0);
      HasPostIncrOp = HasPostIncrOp || (Method->getNumParams() == 1);
      continue;
    }
    if (OPK == OO_Star) {
      HasDerefOp = (Method->getNumParams() == 0);
      continue;
    }
  }

  return HasCopyCtor && HasCopyAssign && HasDtor && HasPreIncrOp &&
         HasPostIncrOp && HasDerefOp;
}

bool isContainerTypeFor(const QualType &Type, const QualType &IteratorType) {
  if (isIteratorType(Type))
    return false;

  const auto *CRD = Type->getUnqualifiedDesugaredType()->getAsCXXRecordDecl();
  return isContainerFor(CRD, IteratorType);
}

bool isContainerFor(const CXXRecordDecl *CRD, const QualType &IteratorType) {
  if (!CRD)
    return false;

  for (const auto *Decl : CRD->decls()) {
    const auto *TD = dyn_cast<TypeDecl>(Decl);
    if (!TD)
      continue;

    if (TD->getTypeForDecl() == IteratorType.getTypePtr())
      return true;
  }

  return false;
}

bool isComparisonOperator(OverloadedOperatorKind OK) {
  return OK == OO_EqualEqual || OK == OO_ExclaimEqual || OK == OO_Less ||
         OK == OO_LessEqual || OK == OO_Greater || OK == OO_GreaterEqual;
}

bool isBeginCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  return IdInfo->getName().endswith_lower("begin");
}

bool isEndCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  return IdInfo->getName().endswith_lower("end");
}

bool isAssignCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() > 2)
    return false;
  return IdInfo->getName() == "assign";
}

bool isClearCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() > 0)
    return false;
  return IdInfo->getName() == "clear";
}

bool isPushBackCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() != 1)
    return false;
  return IdInfo->getName() == "push_back";
}

bool isEmplaceBackCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() < 1)
    return false;
  return IdInfo->getName() == "emplace_back";
}

bool isPopBackCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() > 0)
    return false;
  return IdInfo->getName() == "pop_back";
}

bool isPushFrontCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() != 1)
    return false;
  return IdInfo->getName() == "push_front";
}

bool isEmplaceFrontCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() < 1)
    return false;
  return IdInfo->getName() == "emplace_front";
}

bool isPopFrontCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() > 0)
    return false;
  return IdInfo->getName() == "pop_front";
}

bool isInsertCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() < 2 || Func->getNumParams() > 3)
    return false;
  if (!isIteratorType(Func->getParamDecl(0)->getType()))
    return false;
  if (Func->getNumParams() == 2 &&
      isIteratorType(Func->getParamDecl(1)->getType()))
    return false;
  return IdInfo->getName() == "insert";
}

bool isEmplaceCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() < 2)
    return false;
  if (!isIteratorType(Func->getParamDecl(0)->getType()))
    return false;
  return IdInfo->getName() == "emplace";
}

bool isEraseCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() < 1 || Func->getNumParams() > 2)
    return false;
  if (!isIteratorType(Func->getParamDecl(0)->getType()))
    return false;
  if (Func->getNumParams() == 2 &&
      !isIteratorType(Func->getParamDecl(1)->getType()))
    return false;
  return IdInfo->getName() == "erase";
}

bool isEraseAfterCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() < 1 || Func->getNumParams() > 2)
    return false;
  if (!isIteratorType(Func->getParamDecl(0)->getType()))
    return false;
  if (Func->getNumParams() == 2 &&
      !isIteratorType(Func->getParamDecl(1)->getType()))
    return false;
  return IdInfo->getName() == "erase_after";
}

bool isEmptyCall(const FunctionDecl *Func) {
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() > 0)
    return false;
  return IdInfo->getName() == "empty";
}

bool isStdAdvanceCall(const FunctionDecl *Func) {
  if (!Func->isInStdNamespace())
    return false;
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  return (Func->getNumParams() == 2 && IdInfo->getName() == "advance") ||
         (Func->getNumParams() == 3 && IdInfo->getName() == "__advance");
}

bool isStdPrevCall(const FunctionDecl *Func) {
  if (!Func->isInStdNamespace())
    return false;
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() != 2)
    return false;
  return IdInfo->getName() == "prev";
}

bool isStdNextCall(const FunctionDecl *Func) {
  if (!Func->isInStdNamespace())
    return false;
  const auto *IdInfo = Func->getIdentifier();
  if (!IdInfo)
    return false;
  if (Func->getNumParams() != 2)
    return false;
  return IdInfo->getName() == "next";
}

bool isAssignmentOperator(OverloadedOperatorKind OK) { return OK == OO_Equal; }

bool isSimpleComparisonOperator(OverloadedOperatorKind OK) {
  return OK == OO_EqualEqual || OK == OO_ExclaimEqual;
}

bool isAccessOperator(OverloadedOperatorKind OK) {
  return isDereferenceOperator(OK) || isIncrementOperator(OK) ||
         isDecrementOperator(OK) || isRandomIncrOrDecrOperator(OK);
}

bool isDereferenceOperator(OverloadedOperatorKind OK) {
  return OK == OO_Star || OK == OO_Arrow || OK == OO_ArrowStar ||
         OK == OO_Subscript;
}

bool isIncrementOperator(OverloadedOperatorKind OK) {
  return OK == OO_PlusPlus;
}

bool isDecrementOperator(OverloadedOperatorKind OK) {
  return OK == OO_MinusMinus;
}

bool isRandomIncrOrDecrOperator(OverloadedOperatorKind OK) {
  return OK == OO_Plus || OK == OO_PlusEqual || OK == OO_Minus ||
         OK == OO_MinusEqual;
}

bool hasSubscriptOperator(const MemRegion *Reg) {
  const auto *CRD = getCXXRecordDecl(Reg);
  if (!CRD)
    return false;

  for (const auto *Method : CRD->methods()) {
    if (!Method->isOverloadedOperator())
      continue;
    const auto OPK = Method->getOverloadedOperator();
    if (OPK == OO_Subscript) {
      return true;
    }
  }
  return false;
}

bool frontModifiable(const MemRegion *Reg) {
  const auto *CRD = getCXXRecordDecl(Reg);
  if (!CRD)
    return false;

  for (const auto *Method : CRD->methods()) {
    if (!Method->getDeclName().isIdentifier())
      continue;
    if (Method->getName() == "push_front" || Method->getName() == "pop_front") {
      return true;
    }
  }
  return false;
}

bool backModifiable(const MemRegion *Reg) {
  const auto *CRD = getCXXRecordDecl(Reg);
  if (!CRD)
    return false;

  for (const auto *Method : CRD->methods()) {
    if (!Method->getDeclName().isIdentifier())
      continue;
    if (Method->getName() == "push_back" || Method->getName() == "pop_back") {
      return true;
    }
  }
  return false;
}

const CXXRecordDecl *getCXXRecordDecl(const MemRegion *Reg) {
  QualType Type;
  if (const auto *TVReg = Reg->getAs<TypedValueRegion>()) {
    Type = TVReg->getValueType();
  } else if (const auto *SymReg = Reg->getAs<SymbolicRegion>()) {
    Type = SymReg->getSymbol()->getType();
  } else {
    return nullptr;
  }

  if (const auto *RefT = Type->getAs<ReferenceType>()) {
    Type = RefT->getPointeeType();
  }

  return Type->getUnqualifiedDesugaredType()->getAsCXXRecordDecl();
}

SymbolRef getContainerBegin(ProgramStateRef State, const MemRegion *Cont) {
  const auto *CDataPtr = getContainerData(State, Cont);
  if (!CDataPtr)
    return nullptr;

  return CDataPtr->getBegin();
}

SymbolRef getContainerEnd(ProgramStateRef State, const MemRegion *Cont) {
  const auto *CDataPtr = getContainerData(State, Cont);
  if (!CDataPtr)
    return nullptr;

  return CDataPtr->getEnd();
}

ProgramStateRef createContainerBegin(ProgramStateRef State,
                                     const MemRegion *Cont, const Expr *E,
                                     QualType T, const LocationContext *LCtx,
                                     unsigned BlockCount) {
  // Only create if it does not exist
  const auto *CDataPtr = getContainerData(State, Cont);
  if (CDataPtr && CDataPtr->getBegin())
    return State;

  auto &SymMgr = State->getSymbolManager();
  const SymbolConjured *Sym =
      SymMgr.conjureSymbol(E, LCtx, T, BlockCount, "begin");
  State = assumeNoOverflow(State, Sym, 4);

  if (CDataPtr) {
    const auto CData = CDataPtr->newBegin(Sym);
    if (auto EndSym = CDataPtr->getEnd()) {
      State = ensureNonNegativeDiff(State, EndSym, Sym);
    }
    return setContainerData(State, Cont, CData);
  }

  const auto CData = ContainerData::fromBegin(Sym);
  return setContainerData(State, Cont, CData);
}

ProgramStateRef createContainerEnd(ProgramStateRef State, const MemRegion *Cont,
                                   const Expr *E, QualType T,
                                   const LocationContext *LCtx,
                                   unsigned BlockCount) {
  // Only create if it does not exist
  const auto *CDataPtr = getContainerData(State, Cont);
  if (CDataPtr && CDataPtr->getEnd())
    return State;

  auto &SymMgr = State->getSymbolManager();
  const SymbolConjured *Sym =
      SymMgr.conjureSymbol(E, LCtx, T, BlockCount, "end");
  State = assumeNoOverflow(State, Sym, 4);

  if (CDataPtr) {
    const auto CData = CDataPtr->newEnd(Sym);
    if (auto BeginSym = CDataPtr->getBegin()) {
      State = ensureNonNegativeDiff(State, Sym, BeginSym);
    }
    return setContainerData(State, Cont, CData);
  }

  const auto CData = ContainerData::fromEnd(Sym);
  return setContainerData(State, Cont, CData);
}

const ContainerData *getContainerData(ProgramStateRef State,
                                      const MemRegion *Cont) {
  return State->get<ContainerMap>(Cont);
}

ProgramStateRef setContainerData(ProgramStateRef State, const MemRegion *Cont,
                                 const ContainerData &CData) {
  return State->set<ContainerMap>(Cont, CData);
}

const IteratorPosition *getIteratorPosition(ProgramStateRef State,
                                            const SVal &Val) {
  if (auto Reg = Val.getAsRegion()) {
    Reg = getTopRegion(Reg);
    return State->get<IteratorRegionMap>(Reg);
  } else if (const auto Sym = Val.getAsSymbol()) {
    return State->get<IteratorSymbolMap>(Sym);
  } else if (const auto LCVal = Val.getAs<nonloc::LazyCompoundVal>()) {
    return State->get<IteratorRegionMap>(LCVal->getRegion());
  }
  return nullptr;
}

ProgramStateRef setIteratorPosition(ProgramStateRef State, const SVal &Val,
                                    const IteratorPosition &Pos) {
  if (auto Reg = Val.getAsRegion()) {
    Reg = getTopRegion(Reg);
    return State->set<IteratorRegionMap>(Reg, Pos);
  } else if (const auto Sym = Val.getAsSymbol()) {
    return State->set<IteratorSymbolMap>(Sym, Pos);
  } else if (const auto LCVal = Val.getAs<nonloc::LazyCompoundVal>()) {
    return State->set<IteratorRegionMap>(LCVal->getRegion(), Pos);
  }
  return nullptr;
}

ProgramStateRef removeIteratorPosition(ProgramStateRef State, const SVal &Val) {
  if (auto Reg = Val.getAsRegion()) {
    Reg = getTopRegion(Reg);
    return State->remove<IteratorRegionMap>(Reg);
  } else if (const auto Sym = Val.getAsSymbol()) {
    return State->remove<IteratorSymbolMap>(Sym);
  } else if (const auto LCVal = Val.getAs<nonloc::LazyCompoundVal>()) {
    return State->remove<IteratorRegionMap>(LCVal->getRegion());
  }
  return nullptr;
}

ProgramStateRef copyIteratorPosition(ProgramStateRef State, const SVal &Src,
                                     const SVal &Dest) {
  const auto *Pos = getIteratorPosition(State, Src);
  if (Pos) {
    State = setIteratorPosition(State, Dest, *Pos);
  }
  return State;
}

ProgramStateRef relateSymbols(ProgramStateRef State, SymbolRef Sym1,
                              SymbolRef Sym2, bool Equal) {
  auto &SVB = State->getStateManager().getSValBuilder();

  // FIXME: This code should be reworked as follows:
  // 1. Subtract the operands using evalBinOp().
  // 2. Assume that the result doesn't overflow.
  // 3. Compare the result to 0.
  // 4. Assume the result of the comparison.

  const auto comparison =
      SVB.evalBinOp(State, BO_EQ, nonloc::SymbolVal(Sym1),
                    nonloc::SymbolVal(Sym2), SVB.getConditionType());

  assert(comparison.getAs<DefinedSVal>() &&
         "Symbol comparison must be a `DefinedSVal`");

  auto NewState = State->assume(comparison.castAs<DefinedSVal>(), Equal);
  if (!NewState)
    return nullptr;

  if (const auto CompSym = comparison.getAsSymbol()) {
    assert(isa<SymIntExpr>(CompSym) &&
           "Symbol comparison must be a `SymIntExpr`");
    assert(BinaryOperator::isComparisonOp(
               cast<SymIntExpr>(CompSym)->getOpcode()) &&
           "Symbol comparison must be a comparison");
    return assumeNoOverflow(NewState, cast<SymIntExpr>(CompSym)->getLHS(), 2);
  }

  return NewState;
}

template <typename Condition, typename Process>
ProgramStateRef processIteratorPositions(ProgramStateRef State, Condition Cond,
                                         Process Proc) {
  auto &RegionMapFactory = State->get_context<IteratorRegionMap>();
  auto RegionMap = State->get<IteratorRegionMap>();
  bool Changed = false;
  for (const auto Reg : RegionMap) {
    if (Cond(Reg.second)) {
      RegionMap = RegionMapFactory.add(RegionMap, Reg.first, Proc(Reg.second));
      Changed = true;
    }
  }

  if (Changed)
    State = State->set<IteratorRegionMap>(RegionMap);

  auto &SymbolMapFactory = State->get_context<IteratorSymbolMap>();
  auto SymbolMap = State->get<IteratorSymbolMap>();
  Changed = false;
  for (const auto Sym : SymbolMap) {
    if (Cond(Sym.second)) {
      SymbolMap = SymbolMapFactory.add(SymbolMap, Sym.first, Proc(Sym.second));
      Changed = true;
    }
  }

  if (Changed)
    State = State->set<IteratorSymbolMap>(SymbolMap);

  return State;
}

ProgramStateRef invalidateAllIteratorPositions(ProgramStateRef State,
                                               const MemRegion *Cont) {
  auto MatchCont = [&](const IteratorPosition &Pos) {
    return Pos.getContainer() == Cont;
  };
  auto Invalidate = [&](const IteratorPosition &Pos) {
    return Pos.invalidate();
  };
  return processIteratorPositions(State, MatchCont, Invalidate);
}

ProgramStateRef
invalidateAllIteratorPositionsExcept(ProgramStateRef State,
                                     const MemRegion *Cont, SymbolRef Offset,
                                     BinaryOperator::Opcode Opc) {
  auto MatchContAndCompare = [&](const IteratorPosition &Pos) {
    return Pos.getContainer() == Cont &&
           !compare(State, Pos.getOffset(), Offset, Opc);
  };
  auto Invalidate = [&](const IteratorPosition &Pos) {
    return Pos.invalidate();
  };
  return processIteratorPositions(State, MatchContAndCompare, Invalidate);
}

ProgramStateRef invalidateIteratorPositions(ProgramStateRef State,
                                            SymbolRef Offset,
                                            BinaryOperator::Opcode Opc) {
  auto Compare = [&](const IteratorPosition &Pos) {
    return compare(State, Pos.getOffset(), Offset, Opc);
  };
  auto Invalidate = [&](const IteratorPosition &Pos) {
    return Pos.invalidate();
  };
  return processIteratorPositions(State, Compare, Invalidate);
}

ProgramStateRef invalidateIteratorPositions(ProgramStateRef State,
                                            SymbolRef Offset1,
                                            BinaryOperator::Opcode Opc1,
                                            SymbolRef Offset2,
                                            BinaryOperator::Opcode Opc2) {
  auto Compare = [&](const IteratorPosition &Pos) {
    return compare(State, Pos.getOffset(), Offset1, Opc1) &&
           compare(State, Pos.getOffset(), Offset2, Opc2);
  };
  auto Invalidate = [&](const IteratorPosition &Pos) {
    return Pos.invalidate();
  };
  return processIteratorPositions(State, Compare, Invalidate);
}

ProgramStateRef reassignAllIteratorPositions(ProgramStateRef State,
                                             const MemRegion *Cont,
                                             const MemRegion *NewCont) {
  auto MatchCont = [&](const IteratorPosition &Pos) {
    return Pos.getContainer() == Cont;
  };
  auto ReAssign = [&](const IteratorPosition &Pos) {
    return Pos.reAssign(NewCont);
  };
  return processIteratorPositions(State, MatchCont, ReAssign);
}

ProgramStateRef reassignAllIteratorPositionsUnless(ProgramStateRef State,
                                                   const MemRegion *Cont,
                                                   const MemRegion *NewCont,
                                                   SymbolRef Offset,
                                                   BinaryOperator::Opcode Opc) {
  auto MatchContAndCompare = [&](const IteratorPosition &Pos) {
    return Pos.getContainer() == Cont &&
           !compare(State, Pos.getOffset(), Offset, Opc);
  };
  auto ReAssign = [&](const IteratorPosition &Pos) {
    return Pos.reAssign(NewCont);
  };
  return processIteratorPositions(State, MatchContAndCompare, ReAssign);
}

ProgramStateRef rebaseSymbolInIteratorPositionsIf(
    ProgramStateRef State, SValBuilder &SVB, SymbolRef OldSym, SymbolRef NewSym,
    SymbolRef CondSym, BinaryOperator::Opcode Opc) {
  auto LessThanEnd = [&](const IteratorPosition &Pos) {
    return compare(State, Pos.getOffset(), CondSym, Opc);
  };
  auto RebaseSymbol = [&](const IteratorPosition &Pos) {
    return Pos.setTo(rebaseSymbol(State, SVB, Pos.getOffset(), OldSym, NewSym));
  };
  return processIteratorPositions(State, LessThanEnd, RebaseSymbol);
}

// This function rebases symbolic expression `OldExpr + Int` to `NewExpr + Int`,
// `OldExpr - Int` to `NewExpr - Int` and  `OldExpr` to `NewExpr` in expression
// `OrigExpr`.
SymbolRef rebaseSymbol(ProgramStateRef State, SValBuilder &SVB,
                       SymbolRef OrigExpr, SymbolRef OldExpr,
                       SymbolRef NewSym) {
  auto &SymMgr = SVB.getSymbolManager();
  auto Diff =
      SVB.evalBinOpNN(State, BO_Sub, nonloc::SymbolVal(OrigExpr),
                      nonloc::SymbolVal(OldExpr), SymMgr.getType(OrigExpr));

  const auto DiffInt = Diff.getAs<nonloc::ConcreteInt>();
  if (!DiffInt)
    return OrigExpr;

  return SVB
      .evalBinOpNN(State, BO_Add, *DiffInt, nonloc::SymbolVal(NewSym),
                   SymMgr.getType(OrigExpr))
      .getAsSymbol();
}

ProgramStateRef ensureNonNegativeDiff(ProgramStateRef State, SymbolRef Sym1,
                                      SymbolRef Sym2) {
  // First Try to compare them and get a defined value
  auto &SVB = State->getStateManager().getSValBuilder();

  auto nonNeg = SVB.evalBinOp(State, BO_GE, nonloc::SymbolVal(Sym1),
                              nonloc::SymbolVal(Sym2), SVB.getConditionType())
                    .getAs<DefinedSVal>();

  if (nonNeg) {
    return State->assume(*nonNeg, true);
  }

  return State;
}

bool isPastTheEnd(ProgramStateRef State, const IteratorPosition &Pos) {
  const auto *Cont = Pos.getContainer();
  const auto *CData = getContainerData(State, Cont);
  if (!CData)
    return false;

  const auto End = CData->getEnd();
  if (End) {
    if (isEqual(State, Pos.getOffset(), End)) {
      return true;
    }
  }

  return false;
}

bool isAheadOfRange(ProgramStateRef State, const IteratorPosition &Pos) {
  const auto *Cont = Pos.getContainer();
  const auto *CData = getContainerData(State, Cont);
  if (!CData)
    return false;

  const auto Beg = CData->getBegin();
  if (Beg) {
    if (isLess(State, Pos.getOffset(), Beg)) {
      return true;
    }
  }

  return false;
}

bool isBehindPastTheEnd(ProgramStateRef State, const IteratorPosition &Pos) {
  const auto *Cont = Pos.getContainer();
  const auto *CData = getContainerData(State, Cont);
  if (!CData)
    return false;

  const auto End = CData->getEnd();
  if (End) {
    if (isGreater(State, Pos.getOffset(), End)) {
      return true;
    }
  }

  return false;
}

bool isLess(ProgramStateRef State, SymbolRef Sym1, SymbolRef Sym2) {
  return compare(State, Sym1, Sym2, BO_LT);
}

bool isGreater(ProgramStateRef State, SymbolRef Sym1, SymbolRef Sym2) {
  return compare(State, Sym1, Sym2, BO_GT);
}

bool isEqual(ProgramStateRef State, SymbolRef Sym1, SymbolRef Sym2) {
  return compare(State, Sym1, Sym2, BO_EQ);
}

bool compare(ProgramStateRef State, SymbolRef Sym1, SymbolRef Sym2,
             BinaryOperator::Opcode Opc) {
  return compare(State, nonloc::SymbolVal(Sym1), nonloc::SymbolVal(Sym2), Opc);
}

bool compare(ProgramStateRef State, NonLoc NL1, NonLoc NL2,
             BinaryOperator::Opcode Opc) {
  auto &SVB = State->getStateManager().getSValBuilder();

  const auto comparison =
      SVB.evalBinOp(State, Opc, NL1, NL2, SVB.getConditionType());

  assert(comparison.getAs<DefinedSVal>() &&
         "Symbol comparison must be a `DefinedSVal`");

  return !State->assume(comparison.castAs<DefinedSVal>(), false);
}

const MemRegion *getTopRegion(const MemRegion *Reg) {
  auto TopReg = Reg;
  while (const auto *CBOR = TopReg->getAs<CXXBaseObjectRegion>()) {
    TopReg = CBOR->getSuperRegion();
  }
  return TopReg;
}

} // namespace

void ento::registerIteratorModelling(CheckerManager &mgr) {
  mgr.registerChecker<IteratorChecker>();
}

bool ento::shouldRegisterIteratorModelling(const CheckerManager &mgr) {
  if (!mgr.getLangOpts().CPlusPlus)
    return false;

  if (!mgr.getAnalyzerOptions().ShouldAggressivelySimplifyBinaryOperation) {
    mgr.getASTContext().getDiagnostics().Report(
        diag::err_analyzer_checker_incompatible_analyzer_option)
      << "aggressive-binary-operation-simplification" << "false";
    return false;
  }

  return true;
}

void ento::registerIteratorOutOfRangeChecker(CheckerManager &Mgr) {
  auto *checker = Mgr.getChecker<IteratorChecker>();
  checker->ChecksEnabled[IteratorChecker::CK_IteratorOutOfRangeChecker] = true;
  checker->CheckNames[IteratorChecker::CK_IteratorOutOfRangeChecker] =
    Mgr.getCurrentCheckerName();
  checker->AggressiveEraseModeling =
   Mgr.getAnalyzerOptions().getCheckerBooleanOption(
                               "alpha.ericsson.cpp.IteratorOutOfRange",
                               "AggressiveEraseModeling");
}

bool ento::shouldRegisterIteratorOutOfRangeChecker(const CheckerManager &) {
  return true;
}

#define REGISTER_CHECKER(name)                                                 \
  void ento::register##name(CheckerManager &Mgr) {                             \
    auto *checker = Mgr.getChecker<IteratorChecker>();                         \
    checker->ChecksEnabled[IteratorChecker::CK_##name] = true;                 \
    checker->CheckNames[IteratorChecker::CK_##name] =                          \
        Mgr.getCurrentCheckerName();                                           \
  }                                                                            \
                                                                               \
  bool ento::shouldRegister##name(const CheckerManager &) {                    \
    return true;                                                               \
  }

REGISTER_CHECKER(IteratorMismatchChecker)
REGISTER_CHECKER(InvalidatedIteratorAccessChecker)
