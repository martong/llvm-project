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
#include <map>
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

// Based on SimpleStreamChecker and StreamChecker

namespace {

// TODO: read these from config
const std::set<StringRef> cfg_transactionTypeName = {
    "DicosDbTransaction", "DicosDbCollectionOfOpens", "DicosDbBaseTransaction"};
StringRef cfg_startMethodName = "start";
StringRef cfg_commitMethodName = "commit";
StringRef cfg_rollbackMethodName = "rollback";
const std::set<StringRef> cfg_stateCheckMethodNames{"status",
                                                    "assertGoodStatus"};
// Functions for transaction usage and the position of the transaction object in
// the parameter
const std::set<StringRef> cfg_dbObjectTransaction{
    "create",          "openSafeRead",  "openUpdate",    "openDelete",
    "upgradeSafeRead", "upgradeUpdate", "upgradeDelete", "DOA_create",
    "DOA_open",        "DOA_upgrade"};

StringRef cfg_bugType = "Transaction mismanagement";
StringRef cfg_bugCategory = "TSP";
StringRef cfg_reportDoubleCommitMessage =
    "The transaction was double-committed.";
StringRef cfg_reportUncheckedDeathMessage = "The state of the transaction was "
                                            "never checked after it was "
                                            "committed or rollbacked.";
StringRef cfg_reportUncheckedReuseMessage =
    "The state of the transaction was "
    "not checked after it was committed or rollbacked "
    "and before it was reused.";

StringRef cfg_reportNeverCommitedMessage =
    "The transaction was never commited or rolled back after it was started.";

StringRef cfg_reportUnstartedUseMessage =
    "The transaction was used without being started.";

StringRef cfg_reportUncommitedChangedMessage =
    "The transaction has changes that was not committed or rolledbacked.";

enum class TransactionDeath {
  OK,
  UNCHECKED,
  UNCOMMITED,
};

struct TransactionState {
  bool isStarted() const { return m_isStarted; }
  bool isCommitted() const { return m_isCommitted; }
  bool isChecked() const { return m_isChecked; }
  bool isUsed() const { return m_isUsed; }
  bool isRollbackNeeded() const { return m_isRollbackNeeded; }
  bool isRetry() const { return m_isRetry; }
  SymbolRef getCheckResultSymbol() const { return m_checkResult; }

  TransactionState withStarted(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isStarted = v;
    return ts;
  }

  TransactionState withCommitted(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isCommitted = v;
    if (v) {
      ts.m_isStarted = false;
      ts.m_isChecked = false;
    }
    return ts;
  }

  TransactionState withChecked(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isChecked = v;
    return ts;
  }

  TransactionState withRollbackNeeded(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isRollbackNeeded = v;
    return ts;
  }

  TransactionState withUsed(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isUsed = v;
    if (v) {
      ts.m_isChecked = false;
    }
    return ts;
  }

  TransactionState withCheckCondition(SymbolRef checkResult) const {
    TransactionState ts(*this);
    ts.m_checkResult = checkResult;
    return ts;
  }

  TransactionState withRetry(bool v = true) const {
    TransactionState ts(*this);
    ts.m_isRetry = v;
    return ts;
  }

  void Profile(llvm::FoldingSetNodeID &id) const {
    id.AddBoolean(m_isStarted);
    id.AddBoolean(m_isCommitted);
    id.AddBoolean(m_isChecked);
    id.AddBoolean(m_isUsed);
    id.AddPointer(m_checkResult);
    id.AddBoolean(m_isRollbackNeeded);
    id.AddBoolean(m_isRetry);
  }

  void dump() const {
    std::cout << "Started: " << std::boolalpha << m_isStarted
              << " | Committed: " << m_isCommitted
              << " | Checked state: " << m_isChecked
              << " | Use state: " << m_isUsed
              << " | Rollback needed: " << m_isRollbackNeeded
              << " | Retry needed: " << m_isRetry << std::endl;

    if (m_checkResult)
      m_checkResult->dump();

    std::cout << std::endl;
  }

private:
  bool m_isStarted = false;
  bool m_isCommitted = false;
  bool m_isChecked = false;
  bool m_isUsed = false;
  SymbolRef m_checkResult = nullptr;
  bool m_isRollbackNeeded = true;
  bool m_isRetry = false;
};

using TransactionStateRef = const TransactionState *const;
using MemRegionRef = const MemRegion *;

bool operator==(const TransactionState &lhs, const TransactionState &rhs) {
  return lhs.isStarted() == rhs.isStarted() &&
         lhs.isCommitted() == rhs.isCommitted() &&
         lhs.isChecked() == rhs.isChecked() && lhs.isUsed() == rhs.isUsed() &&
         lhs.getCheckResultSymbol() == rhs.getCheckResultSymbol() &&
         lhs.isRollbackNeeded() == rhs.isRollbackNeeded() &&
         lhs.isRetry() == rhs.isRetry();
}

} // namespace

REGISTER_MAP_WITH_PROGRAMSTATE(TransactionStateMap, MemRegionRef,
                               TransactionState)

namespace {

/*
Current limitations:
 - usage of derived transaction type is not handled properly
 - calling transaction methods through 'this' is not handled properly

 - when the transaction object is allocated on the heap, it is not tracked
 - inter-procedural analysis (when within the same TU) works, except with ctors
and dtors
*/

// TODO: also track objects of derived classes
// TODO: check must be done between usages

// TODO: 'operator new' is currently not supported by clang static analyzer
// TODO: do not use getNameAsString(), as it is expensive - try using getName()
// instead, or work with CallEvent::getCalleeIdentifier()?

class DbnTransactionManagementChecker
    : public Checker<eval::Assume, check::PreCall, check::PostCall,
                     check::DeadSymbols, check::RegionChanges> {
public:
  using MemRegionVector = llvm::SmallVector<MemRegionRef, 1>;

  // Check and update program state according to if we are in a branch that a
  // transaction is failed
  ProgramStateRef evalAssume(ProgramStateRef state, SVal cond,
                             bool assumption) const {
    TransactionStateMapTy transactionStates = state->get<TransactionStateMap>();

    if (transactionStates.isEmpty())
      return state;

    ConstraintManager &cmgr = state->getConstraintManager();

    for (TransactionStateMapTy::iterator it = transactionStates.begin(),
                                         end = transactionStates.end();
         it != end; ++it) {

      const TransactionState &transState = it.getData();

      const llvm::APSInt *result =
          cmgr.getSymVal(state, transState.getCheckResultSymbol());

      if (result) {
        switch(result->getLimitedValue()) {
        default:
          break;
        case 0:
        case 2:
          state = state->set<TransactionStateMap>(
              it.getKey(), transState.withRollbackNeeded(false));
          break;
        case 1:
          state = state->set<TransactionStateMap>(
              it.getKey(), transState.withRetry().withRollbackNeeded(false));
          break;
        }
      }
    }
    return state;
  }

  // NOTE: for the error report to reflect the exact line where the problem is,
  // you have to report it from checkPreCall however, keep in mind that you
  // CANNOT access to the SVal that is created as the result of the call in
  // checkPreCall - use checkPostCall for that instead
  void checkPreCall(const CallEvent &call, CheckerContext &context) const {
    if (!_isRelevantCall(call))
      return;

    ProgramStateRef programState = context.getState();

    const auto *func = dyn_cast<FunctionDecl>(call.getDecl());
    const std::string name = func->getNameAsString();

    MemRegionRef transactionMemRegion = nullptr;
    bool isTransactionUsage = false;
    if (dyn_cast<CXXInstanceCall>(&call)) {
      transactionMemRegion = _getMostDerivedRegion(programState, call);
    } else {
      // If it is a static function, check if it is a function that actually
      // uses the transaction
      int pos = _getTransactionParameterPos(call, name);
      if (pos >= 0) {
        transactionMemRegion = call.getArgSVal(pos).getAsRegion();
        isTransactionUsage = true;
      } else {
        return;
      }
    }

    if (!transactionMemRegion) {
      /*std::cout << "!! CXXInstanceCall to an SVal that is not a MemRegion: "
                << std::endl;
      instanceCall->getCXXThisVal().dump();
      std::cout << std::endl;*/
      return;
    }

    const TransactionState *currentState =
        programState->get<TransactionStateMap>(transactionMemRegion);
    if (!currentState) {
      return;
    }

    llvm::SmallVector<StringRef, 1> reportMessages;

    if (isTransactionUsage) {
      programState = programState->set<TransactionStateMap>(
          transactionMemRegion, currentState->withUsed());
      if (!currentState->isStarted()) {
        reportMessages.push_back(cfg_reportUnstartedUseMessage);
      }

    } else if (call.getKind() == CE_CXXDestructor) {
      // call to user written dtor only compiler generated dtors are recognised
      // by checkDeadSymbols (but they don't appear as dtor calls) for all the
      // others, we need to monitor the death manually

      TransactionDeath deathState =
          _CheckTransactionDeath(programState, transactionMemRegion);

      if (deathState == TransactionDeath::UNCHECKED) {
        reportMessages.push_back(cfg_reportUncheckedDeathMessage);
      } else if (deathState == TransactionDeath::UNCOMMITED) {
        reportMessages.push_back(cfg_reportNeverCommitedMessage);
      }

      if (deathState != TransactionDeath::OK) {
        programState =
            programState->remove<TransactionStateMap>(transactionMemRegion);
      }

    } else if (name == cfg_startMethodName) {
      // start call

      // reset the transaction state
      programState = programState->set<TransactionStateMap>(
          transactionMemRegion, TransactionState().withStarted());

      if (currentState->isCommitted() &&
          !currentState->isChecked()) // check the old state, before reset
      {
        // instance re-use after not checking the transaction's state after
        // commit
        reportMessages.push_back(cfg_reportUncheckedReuseMessage);
      }
      if (currentState->isUsed() && !currentState->isCommitted() &&
          !currentState->isRetry()) {
        reportMessages.push_back(cfg_reportUncommitedChangedMessage);
      }
    } else if (name == cfg_commitMethodName) {
      // commit call
      if (currentState->isCommitted()) {
        // double commit
        reportMessages.push_back(cfg_reportDoubleCommitMessage);
      } else {
        // record the fact that the transaction has been committed
        programState = programState->set<TransactionStateMap>(
            transactionMemRegion, currentState->withCommitted());
      }
    } else if (name == cfg_rollbackMethodName ||
      // Rollbacked transaction needs not to be checked. Treat it as checked.
               cfg_stateCheckMethodNames.find(name) !=
               cfg_stateCheckMethodNames.end()) {
      // state check call: record the fact that the state of the transaction has
      // been checked
      programState = programState->set<TransactionStateMap>(
          transactionMemRegion, currentState->withChecked());
    }

    ExplodedNode *node = context.addTransition(programState);

    // FIXME: why nullptr in some cases?
    if (!node)
      return;

    // report the errors, if any
    if (!m_bugType) {
      m_bugType =
          std::make_unique<BugType>(this, cfg_bugType, cfg_bugCategory);
    }
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
    std::vector<TransactionDeath> reasons;

    for (auto transactionInfo : trackedTransactions) {
      MemRegionRef transactionMemRegion = transactionInfo.first;

      if (symbolReaper.isLiveRegion(transactionMemRegion)) {
        continue;
      }

      TransactionDeath deathState =
          _CheckTransactionDeath(programState, transactionMemRegion);

      programState =
          programState->remove<TransactionStateMap>(transactionMemRegion);

      if (deathState == TransactionDeath::OK) {
        continue;
      }

      transactionRegionsToReport.push_back(transactionMemRegion);
      reasons.push_back(deathState);
    }

    ExplodedNode *node = context.addTransition(programState);

    // FIXME: investigate why can this happen
    if (node == nullptr)
      return;

    _reportTransactions(transactionRegionsToReport, context, node, reasons);
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
                cfg_dbObjectTransaction.end());
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

  // Check which parameter is a reference to a transaction and return its
  // position or -1 if not found
  int _getTransactionParameterPos(const CallEvent &call,
                                  const std::string &name) const {
    if (cfg_dbObjectTransaction.count(name) == 0)
      return -1;

    auto paramTypeIt = call.param_type_begin();
    for (unsigned i = 0, num = call.getNumArgs();
         i < num && paramTypeIt != call.param_type_end(); ++i, ++paramTypeIt) {

      const auto *refType = (*paramTypeIt)->getAs<ReferenceType>();

      const RecordType *paramType =
          refType ? refType->getPointeeType()->getAs<RecordType>() : nullptr;

      if (paramType) {
        const RecordDecl *decl = paramType->getDecl();
        if (cfg_transactionTypeName.count(decl->getName().str()))
          return i;
      }
    }

    return -1;
  }

  TransactionDeath
  _CheckTransactionDeath(const ProgramStateRef &programState,
                         MemRegionRef transactionMemRegion) const {
    const TransactionState *transactionState =
        programState->get<TransactionStateMap>(transactionMemRegion);

    if (!transactionState)
      return TransactionDeath::OK;

    if (transactionState->isUsed() && transactionState->isChecked() &&
        !transactionState->isRollbackNeeded()) {
      return TransactionDeath::OK;
    }

    if (transactionState->isCommitted() && !transactionState->isChecked()) {
      return TransactionDeath::UNCHECKED;
    }

    if (transactionState->isUsed() && !transactionState->isCommitted()) {
      return TransactionDeath::UNCOMMITED;
    }

    return TransactionDeath::OK;
  }

  void _reportTransactions(const MemRegionVector &transactionRegions,
                           CheckerContext &context, ExplodedNode *errorNode,
                           const std::vector<TransactionDeath> &reasons) const {
    if (!m_bugType) {
      m_bugType =
          std::make_unique<BugType>(this, cfg_bugType, cfg_bugCategory);
    }

    for (size_t i = 0; i < transactionRegions.size(); ++i) {
      auto r = std::make_unique<PathSensitiveBugReport>(
          *m_bugType,
          (reasons[i] == TransactionDeath::UNCHECKED)
              ? cfg_reportUncheckedDeathMessage
              : cfg_reportNeverCommitedMessage,
          errorNode);
      r->markInteresting(transactionRegions[i]);
      context.emitReport(std::move(r));
    }
  }

  mutable std::unique_ptr<BugType> m_bugType;
};

} // namespace
void ento::registerDbnTransactionManagementChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<DbnTransactionManagementChecker>();
}

bool ento::shouldRegisterDbnTransactionManagementChecker(
    const CheckerManager &mgr) {
  return true;
}
