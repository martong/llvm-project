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

#include <iostream>
#include <set>
#include <string>

#include "llvm/ADT/Optional.h"
#include "llvm/Support/raw_ostream.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;

namespace {
StringRef cfg_bugType = "Missing delay between transaction retries";
StringRef cfg_bugCategory = "MTAS";

// TODO: lot of replication from TSP_DBN_TRANSACTION_MANAGEMENT
const std::set<StringRef> cfg_transactionTypeName = {
    "DicosDbTransaction", "DicosDbCollectionOfOpens", "DicosDbBaseTransaction"};

StringRef cfg_startMethodName = "start";

const std::set<StringRef> cfg_dbObjectTransaction{
    "create",          "openSafeRead",  "openUpdate",    "openDelete",
    "upgradeSafeRead", "upgradeUpdate", "upgradeDelete", "DOA_create",
    "DOA_open",        "DOA_upgrade"};

StringRef cfg_delayFunctionName = "Dicos_delay";

StringRef cfg_reportMissingDelay = "There is no delay between retries.";

struct TransactionState {
  SymbolRef getCheckResultSymbol() const { return m_checkResult; }
  bool isStarted() const { return m_isStarted; }
  bool isRetry() const { return m_isRetry; }
  bool isDelayed() const { return m_isDelayed; }

  TransactionState withStarted(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isStarted = v;
    if (v) {
      ts.m_isDelayed = ts.m_isRetry = false;
    }
    return ts;
  }

  TransactionState withDelayed(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isDelayed = v;
    return ts;
  }

  TransactionState withRetry(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isRetry = v;
    if (v) {
      ts.m_isDelayed = false;
    }
    return ts;
  }

  TransactionState withCheckCondition(SymbolRef checkResult) const {
    TransactionState ts(*this);
    ts.m_checkResult = checkResult;
    return ts;
  }

  void Profile(llvm::FoldingSetNodeID &id) const {
    id.AddBoolean(m_isStarted);
    id.AddBoolean(m_isRetry);
    id.AddBoolean(m_isDelayed);
    id.AddPointer(m_checkResult);
  }

  void dump() const {
    std::cout << "Started: " << std::boolalpha << m_isStarted
              << " | Retry: " << m_isRetry << " | Delayed: " << m_isDelayed
              << std::endl;

    if (m_checkResult)
      m_checkResult->dump();

    std::cout << std::endl;
  }

private:
  bool m_isStarted = false;
  SymbolRef m_checkResult = nullptr;
  bool m_isRetry = false;
  bool m_isDelayed = false;
};

bool operator==(const TransactionState &lhs, const TransactionState &rhs) {
  return lhs.isStarted() == rhs.isStarted() && lhs.isRetry() == rhs.isRetry() &&
         lhs.isDelayed() == rhs.isDelayed() &&
         lhs.getCheckResultSymbol() == rhs.getCheckResultSymbol();
}

using TransactionStateRef = const TransactionState *const;
using MemRegionRef = const MemRegion *;
} // namespace

REGISTER_MAP_WITH_PROGRAMSTATE(TransactionStateMap, MemRegionRef,
                               TransactionState)

namespace {
class DbnDelayAfterRetryChecker
    : public Checker<eval::Assume, check::PreCall, check::PostCall,
                     check::DeadSymbols, check::RegionChanges> {
public:
  typedef llvm::SmallVector<MemRegionRef, 1> MemRegionVector;

  // Check if we are on an exection path that needs retry of a transaction
  ProgramStateRef evalAssume(ProgramStateRef state, SVal cond,
                             bool assumption) const {
    TransactionStateMapTy transactionStates = state->get<TransactionStateMap>();

    if (transactionStates.isEmpty())
      return state;

    ConstraintManager &cmgr = state->getConstraintManager();

    for (auto it : transactionStates) {
      const TransactionState &transState = it.second;

      const llvm::APSInt *result =
          cmgr.getSymVal(state, transState.getCheckResultSymbol());

      if (result) {
        if (result->getLimitedValue() == 1) {
          state =
              state->set<TransactionStateMap>(it.first, transState.withRetry());
        }
      }
    }

    return state;
  }

  void checkPreCall(const CallEvent &call, CheckerContext &context) const {
    if (!_isRelevantCall(call))
      return;

    ProgramStateRef programState = context.getState();

    const auto *func = dyn_cast<FunctionDecl>(call.getDecl());
    const std::string name = func->getNameAsString();

    MemRegionRef transactionMemRegion = nullptr;
    if (isa<CXXInstanceCall>(&call)) {
      transactionMemRegion = _getMostDerivedRegion(programState, call);
    } else {
      // Call to delay function
      // All transaction that is in retry state should be in delayed state now
      // in this execution path
      TransactionStateMapTy transactionStates =
          programState->get<TransactionStateMap>();

      for (auto it : transactionStates) {
        const TransactionState &transState = it.second;

        if (transState.isRetry()) {
          programState = programState->set<TransactionStateMap>(
              it.first, transState.withDelayed());
        }
      }

      context.addTransition(programState);
      return;
    }

    const TransactionState *currentState =
        programState->get<TransactionStateMap>(transactionMemRegion);

    if (!currentState) {
      return;
    }

    SmallVector<StringRef, 1> reportMessages;

    if (call.getKind() == CE_CXXDestructor) {
      programState =
          programState->remove<TransactionStateMap>(transactionMemRegion);
    } else if (name == cfg_startMethodName) {
      if (currentState->isRetry() && !currentState->isDelayed()) {
        reportMessages.push_back(cfg_reportMissingDelay);
      }

      programState = programState->set<TransactionStateMap>(
          transactionMemRegion, TransactionState().withStarted());
    }

    ExplodedNode *node = context.addTransition(programState);

    // FIXME: why nullptr in some cases?
    if (!node)
      return;

    if (!m_bugType)
      m_bugType = std::make_unique<clang::ento::BugType>(this, cfg_bugType,
                                                         cfg_bugCategory);

    // report the errors, if any
    for (StringRef msg : reportMessages) {
      auto r = std::make_unique<PathSensitiveBugReport>(*m_bugType, msg, node);
      r->markInteresting(transactionMemRegion);
      context.emitReport(std::move(r));
    }
  }

  void checkPostCall(const CallEvent &call, CheckerContext &context) const {
    if (!_isRelevantCall(call))
      return;

    ProgramStateRef programState = context.getState();

    if (call.getKind() == CE_CXXConstructor) {
      const auto *func = dyn_cast<CXXConstructorDecl>(call.getDecl());

      if (func->getParent()->getName() != "DicosDbTransaction")
        return;

      // start tracking transaction object
      SVal createdSVal = programState->getSVal(call.getOriginExpr(),
                                               context.getLocationContext());

      MemRegionRef memRegion = createdSVal.getAsRegion();
      if (!memRegion) {
        auto LCV = createdSVal.getAs<nonloc::LazyCompoundVal>();
        if (LCV) {
          memRegion = LCV->getRegion();
        }
      }

      if (memRegion) {
        programState = programState->set<TransactionStateMap>(
            memRegion, TransactionState().withStarted());
        context.addTransition(programState);
      }
    } else {
      const auto *func = dyn_cast<FunctionDecl>(call.getDecl());
      const std::string name = func->getNameAsString();

      // TODO: config
      if (name == "status") {
        MemRegionRef transactionMemRegion =
            _getMostDerivedRegion(programState, call);

        const TransactionState *currentState =
            programState->get<TransactionStateMap>(transactionMemRegion);

        if (!currentState)
          return;

        TransactionState newState = currentState->withCheckCondition(
            call.getReturnValue().getAsSymbol());

        programState = programState->set<TransactionStateMap>(
            transactionMemRegion, newState);

        context.addTransition(programState);
      }
    }
  }

  void checkDeadSymbols(SymbolReaper &symbolReaper,
                        CheckerContext &context) const {
    ProgramStateRef programState = context.getState();
    TransactionStateMapTy trackedTransactions =
        programState->get<TransactionStateMap>();
    MemRegionVector transactionRegionsToReport;

    for (auto transactionInfo : trackedTransactions) {
      MemRegionRef transactionMemRegion = transactionInfo.first;

      if (symbolReaper.isLiveRegion(transactionMemRegion)) {
        continue;
      }

      programState =
          programState->remove<TransactionStateMap>(transactionMemRegion);
    }
    context.addTransition(programState);
  }

  ProgramStateRef
  checkRegionChanges(ProgramStateRef State,
                     const InvalidatedSymbols *Invalidated,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> Regions,
                     const LocationContext *LCtx, const CallEvent *Call) const {
    MemRegionRef thisRegion =
        Call ? _getMostDerivedRegion(State, *Call) : nullptr;
    // Relevant calls are modelled, no need for invalidation.
    if (Call && _isRelevantCall(*Call))
      return State;
    for (auto Region : Regions) {
      // Do not invalidate the transaction when a method was called on it.
      if (Region == thisRegion)
        continue;
      State = State->remove<TransactionStateMap>(Region);
    }
    return State;
  }

private:
  // TODO: replication from TSP_DBN_TRANSACTION_MANAGEMENT, maybe a DBN
  // transaction library should be added?
  MemRegionRef _getMostDerivedRegion(const ProgramStateRef &programState,
                                     const CallEvent &call) const {
    const auto *instanceCall = dyn_cast<CXXInstanceCall>(&call);
    if (!instanceCall)
      return nullptr;
    const auto *transactionMemRegion =
        instanceCall->getCXXThisVal().getAsRegion();
    if (!transactionMemRegion)
      return nullptr;
    const auto *transactionSubRegion = transactionMemRegion->getAs<SubRegion>();

    while (transactionSubRegion &&
           !programState->get<TransactionStateMap>(transactionSubRegion)) {
      transactionSubRegion =
          transactionSubRegion->getSuperRegion()->getAs<SubRegion>();
    }

    return transactionSubRegion;
  }

  bool _isRelevantCall(const CallEvent &call) const {
    const Decl *d = call.getDecl();
    if (!d)
      return false;
    const auto *func = dyn_cast<FunctionDecl>(d);
    return func && !call.isInSystemHeader() &&
           (_isTransactionType(func->getParent()) ||
            cfg_dbObjectTransaction.find(func->getNameAsString()) !=
                cfg_dbObjectTransaction.end() ||
            func->getNameAsString() == cfg_delayFunctionName);
  }

  bool _isTransactionType(const DeclContext *record) const {
    if (!record)
      return false;

    const DeclContext *parent = record;
    while (const auto *parentRecord = dyn_cast<CXXRecordDecl>(parent)) {
      if (cfg_transactionTypeName.count(parentRecord->getName().str())) {
        return true;
      }

      parent = parent->getParent();
    }

    return false;
  }

  mutable std::unique_ptr<BugType> m_bugType;
};
} // namespace

void ento::registerDbnDelayAfterRetryChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<DbnDelayAfterRetryChecker>();
}

bool ento::shouldRegisterDbnDelayAfterRetryChecker(const CheckerManager &mgr) {
  return true;
}
