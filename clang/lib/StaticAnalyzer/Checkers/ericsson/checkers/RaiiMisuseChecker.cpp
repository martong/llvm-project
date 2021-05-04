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
#include <string>

#include "llvm/ADT/ImmutableMap.h"

#include "clang/Basic/SourceManager.h"

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"

#include "CheckerUtils/Buffer.h"
#include "CheckerUtils/Common.h"
#include "CheckerUtils/DumpHelper.h"

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

// This checker is a Clang port of the Coverity CTOR_DTOR_LEAK checker.

namespace {
StringRef cfg_bugName = "Ctor/dtor leak";
StringRef cfg_bugCategory = "C++";
StringRef cfg_reportMessage =
    "A resource allocated by the class ctor is not freed by the dtor.";
StringRef cfg_mismatchReportMessage =
    "The resource allocator and deallocator do not match.";

enum class AllocationType { None = 0, Singleton = 1, Array = 2 };

DumpHelper dumpAllocationType(AllocationType allocType) {
  return DumpHelper([=](std::ostream &os) {
    switch (allocType) {
    case AllocationType::None:
      os << "None";
      break;
    case AllocationType::Singleton:
      os << "Singleton";
      break;
    case AllocationType::Array:
      os << "Array";
      break;
    default:
      os << "(Unknown)";
      break;
    }
  });
}

struct ResourceValue {
  const SymbolRef value; // const SymExpr*
  const AllocationType allocType;
  const PathDiagnosticLocation diagLocation;
  const bool isDeallocated;

  ResourceValue(SymbolRef value_, AllocationType allocType_,
                PathDiagnosticLocation diagLoc_, bool isDeallocated_ = false)
      : value(value_), allocType(allocType_), diagLocation(diagLoc_),
        isDeallocated(isDeallocated_) {}

  ResourceValue withDeallocated(bool v = true) const {
    return {value, allocType, diagLocation, v};
  }

  void Profile(llvm::FoldingSetNodeID &id) const {
    id.AddPointer(value);
    id.AddInteger(static_cast<unsigned>(allocType));
    diagLocation.Profile(id);
    id.AddBoolean(isDeallocated);
  }

  void dump() const {
    std::cout << "ResourceValue{value = " << dumpPtr(value) << "; allocType = ";
    dumpAllocationType(allocType);
    std::cout << "; isDeallocated = " << std::boolalpha << isDeallocated << "}"
              << std::flush;
  }
};

bool operator==(const ResourceValue &lhs, const ResourceValue &rhs) {
  return lhs.value == rhs.value && lhs.allocType == rhs.allocType &&
         lhs.isDeallocated == rhs.isDeallocated;
}

using MemRegionRef = const MemRegion *;
} // namespace

// object region => fieldRegion => ResourceValue{fieldValue, allocatorType}
typedef llvm::ImmutableMapRef<const FieldRegion *, ResourceValue>
    ResourceValueMap;
typedef llvm::ImmutableMapRef<const FieldRegion *, ResourceValue>::FactoryTy
    ResourceValueMapFactory;
REGISTER_MAP_WITH_PROGRAMSTATE(ObjectResourceMap, MemRegionRef,
                               ResourceValueMap)

// TODO: would it be possible to unique the bugreports based on only the
// FieldDecl?

namespace {

class RaiiMisuseChecker
    : public Checker<check::Bind, check::PreStmt<CXXDeleteExpr>,
                     check::PostCall, check::RegionChanges> {
public:
  RaiiMisuseChecker()
      : m_resourceMapFactory(new ResourceValueMapFactory),
        m_emptyResourceValueMap(
            ResourceValueMap::getEmptyMap(m_resourceMapFactory)) {}

  ~RaiiMisuseChecker() override { delete m_resourceMapFactory; }

  void checkBind(const SVal &location, const SVal &value, const Stmt *stmt,
                 CheckerContext &context) const {
    const auto *ctor =
        dyn_cast<CXXConstructorDecl>(context.getLocationContext()->getDecl());
    if (!ctor || isInSysHeader(ctor, context.getSourceManager())) {
      return;
    }

    ProgramStateRef state = context.getState();

    using namespace clang::ast_matchers;

    auto nodes = match(
        binaryOperator(hasOperatorName("="),
                       hasLHS(memberExpr(hasObjectExpression(cxxThisExpr()))
                                  .bind("memberExpr")),
                       hasRHS(cxxNewExpr().bind("newExpr"))),
        *stmt, context.getASTContext());

    if (!nodes.empty()) {
      const auto *NewExpr = nodes[0].getNodeAs<CXXNewExpr>("newExpr");
      AllocationType allocType =
          (NewExpr->isArray() ? AllocationType::Array
                              : AllocationType::Singleton);
      if (NewExpr->getNumPlacementArgs() > 0)
        return;

      const auto *fieldRegion = location.getAsRegion()->getAs<FieldRegion>();
      MemRegionRef objRegion = fieldRegion->getBaseRegion();

      PathDiagnosticLocation diagLocation(stmt, context.getSourceManager(),
                                          context.getLocationContext());

      // check if there exists an explicit (user-implemented) dtor - if not, we
      // can immediately issue the warning
      const CXXDestructorDecl *dtor = ctor->getParent()->getDestructor();
      if (!dtor || !dtor->isUserProvided()) // dtor->isImplicitlyDefined()
      {
        // implicit dtor, issue warning
        auto report = createReport(cfg_reportMessage, diagLocation);
        // FIXME: Was: `report->markInteresting(objRegion);`
        //        and  `report->markInteresting(fieldRegion);`
        // `BasicBugReport` does not have `markIntersting()`
        // `PathSensitiveBugReport` needs `ExplodedNode` constructor parameter
        context.emitReport(std::move(report));

        return; // do not start tracking state pointlessly
      }

      context.addTransition(_registerResourceValue(
          state, objRegion, fieldRegion,
          ResourceValue(value.getAsSymbol(), allocType, diagLocation)));
    }
  }

  // this delete also causes the symbol to die, so it can be checked using
  // checkDeadSymbols: unfortunately, at that point, it's impossible to tell the
  // FieldRegion that contained it
  void checkPreStmt(const CXXDeleteExpr *delExpr,
                    CheckerContext &context) const {
    const auto *dtor =
        dyn_cast<CXXDestructorDecl>(context.getLocationContext()->getDecl());
    if (!dtor) {
      return;
    }

    AllocationType deallocType =
        (delExpr->isArrayForm() ? AllocationType::Array
                                : AllocationType::Singleton);

    ProgramStateRef state = context.getState();
    MemRegionManager &memRegionManager =
        context.getStoreManager().getRegionManager(); // this is actually a very
                                                      // useful class

    if (const auto *memberExpr = llvm::dyn_cast<MemberExpr>(
            delExpr->getArgument()->IgnoreImpCasts())) {
      const FieldDecl *fieldDecl =
          llvm::dyn_cast<FieldDecl>(memberExpr->getMemberDecl());

      // NOTE: in the future, use SValBuilder::getCXXThis() for this instead
      // (http://clang.llvm.org/doxygen/classclang_1_1ento_1_1SValBuilder.html#aac85769beb3533687aaa604f9cdb6a0d)
      const CXXThisRegion *thisRegion = memRegionManager.getCXXThisRegion(
          dtor->getThisType(), context.getLocationContext());

      const SubRegion *thisObjectRegion = context.getState()
                                              ->getSVal(thisRegion)
                                              .getAsRegion()
                                              ->getAs<SubRegion>();

      const FieldRegion *fieldRegion =
          memRegionManager.getFieldRegion(fieldDecl, thisObjectRegion);

      const ResourceValueMap *map =
          state->get<ObjectResourceMap>(thisObjectRegion);
      if (map) {
        const ResourceValue *resourceVal = map->lookup(fieldRegion);
        if (!resourceVal)
          return;

        if (resourceVal->allocType != deallocType) {

          auto report = createReport(
              cfg_mismatchReportMessage,
              PathDiagnosticLocation(delExpr, context.getSourceManager(),
                                     context.getLocationContext()));
        // FIXME: Was: `report->markInteresting(thisObjectRegion);`
        //        and  `report->markInteresting(fieldRegion);`
        // `BasicBugReport` does not have `markIntersting()`
        // `PathSensitiveBugReport` needs `ExplodedNode` constructor parameter
          context.emitReport(std::move(report));

          // we have apparently tried to deallocate the resource, so we mark it
          // as deallocated
        }

        state = state->set<ObjectResourceMap>(
            thisObjectRegion,
            map->add(fieldRegion, resourceVal->withDeallocated(true)));
        context.addTransition(state);
      }
    }
  }

  void checkPostCall(const CallEvent &call, CheckerContext &context) const {
    const CXXDestructorCall *dtorCallPtr;
    if (!(dtorCallPtr = dyn_cast<CXXDestructorCall>(&call))) {
      return;
    }

    const CXXDestructorCall &dtorCall = *dtorCallPtr;

    ProgramStateRef state = context.getState();
    MemRegionRef objectRegion = dtorCall.getCXXThisVal().getAsRegion();

    const ResourceValueMap *map = state->get<ObjectResourceMap>(objectRegion);
    if (map) {
      for (auto it = map->begin(), endIt = map->end(); it != endIt; ++it) {

        const ResourceValue resourceVal = it.getData();
        if (!resourceVal.isDeallocated) {
          auto report =
              createReport(cfg_reportMessage, resourceVal.diagLocation);
          context.emitReport(std::move(report));
        }
      }

      // clean up
      state = state->remove<ObjectResourceMap>(objectRegion);
      context.addTransition(state);
    }
  }

  ProgramStateRef
  checkRegionChanges(ProgramStateRef State,
                     const InvalidatedSymbols *Invalidated,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> Regions,
                     const LocationContext *LCtx, const CallEvent *Call) const {

    const auto *ctor = dyn_cast_or_null<CXXConstructorDecl>(LCtx->getDecl());
    if (!ctor)
      return State;
    for (auto Region : Regions) {
      State = State->remove<ObjectResourceMap>(Region);
    }
    return State;
  }

private:
  RaiiMisuseChecker(const RaiiMisuseChecker &) = delete;
  RaiiMisuseChecker(RaiiMisuseChecker &&) = delete;
  RaiiMisuseChecker &operator=(const RaiiMisuseChecker &) = delete;
  RaiiMisuseChecker &operator=(RaiiMisuseChecker &&) = delete;

  ProgramStateRef _registerResourceValue(ProgramStateRef state,
                                         MemRegionRef hostObject,
                                         const FieldRegion *field,
                                         ResourceValue resourceValue) const {
    const ResourceValueMap *map = state->get<ObjectResourceMap>(hostObject);
    if (!map) {
      state =
          state->set<ObjectResourceMap>(hostObject, m_emptyResourceValueMap);
      map = state->get<ObjectResourceMap>(hostObject);
    }

    state = state->set<ObjectResourceMap>(
        hostObject,
        map->add(field, resourceValue)); // note: map->add overwrites if
                                         // the key is already present
    return state;
  }

  std::unique_ptr<BasicBugReport> createReport(StringRef reportMsg,
                                          PathDiagnosticLocation loc) const {
    if (!m_bugType)
      m_bugType = std::make_unique<clang::ento::BugType>(this, cfg_bugName,
                                                         cfg_bugCategory);
    return std::make_unique<BasicBugReport>(*m_bugType, reportMsg, loc);
  }

  mutable std::unique_ptr<BugType> m_bugType;

  ResourceValueMapFactory *m_resourceMapFactory;
  ResourceValueMap m_emptyResourceValueMap;
};

} // end namespace

void ento::registerRaiiMisuseChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<RaiiMisuseChecker>();
}

bool ento::shouldRegisterRaiiMisuseChecker(const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
