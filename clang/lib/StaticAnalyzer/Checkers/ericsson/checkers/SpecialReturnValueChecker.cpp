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

//==- SpecialReturnValueChecker.cpp ------------------------------*- C++ -*-==//
// This checker tests whether the return value of certain calls are checked
// against a concrete value. Typical examples are functions which return
// negative integers or null pointers in error cases. This checker does not
// emit warnings but instead splits the exploded graph after the call to two
// branches: one branch is the error branch, where the return value falls in the
// error-range while the other branch is the normal branch where it falls
// outside of this range. Other chers (e.g. core checkers) are expected to find
// a bug in the error case (e.g. negative indexing of an array or null pointer
// dereference). The split should not decrease the performance significantly
// since in most cases a branch statement follows shortly the function call
// which does the same split. In error cases we expect to fail one of the
// branches shortly.
//
// The USRs (Unified Symbol Resolution) of functions whose return value is to
// be checked against a concrete value must be listed in a YAML file called
// `SpecialReturn.yaml` together with the concrete value to check against and
// the relation between the return value and this concrete value. Valid
// relation names are `EQ`, `NE`, `LT`, `GT`, `LE`, `GE`. The location of this
// file must be passed to the checker as analyzer option `api-metadata-path`.
//
// Example YAML file:
//
//--- SpecialReturn.yaml -----------------------------------------------------//
//
// #
// # SpecialReturn metadata format 1.0
//
// {name: "c:@F@negative_return", relation: LT, value: 0}
// {name: "c:@F@null_return", relation: EQ, value: 0}
//
//----------------------------------------------------------------------------//
//
// To auto-generate this YAML file on statistical base see checker
// `statisticsCollector.SpecialReturnValue`.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/Index/USRGeneration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "llvm/Support/YAMLTraits.h"

#include "CheckerUtils/LoadMetadata.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

namespace {

struct FuncRetValToCheck {
  std::string Name;
  BinaryOperator::Opcode Rel;
  llvm::APSInt Val;
  bool operator<(const FuncRetValToCheck &rhs) const { return Name < rhs.Name; }
};

} // namespace

LLVM_YAML_IS_DOCUMENT_LIST_VECTOR(FuncRetValToCheck)

namespace llvm {
namespace yaml {

template <> struct ScalarEnumerationTraits<BinaryOperator::Opcode> {
  static void enumeration(IO &io, BinaryOperator::Opcode &value) {
    io.enumCase(value, "EQ", BO_EQ);
    io.enumCase(value, "NE", BO_NE);
    io.enumCase(value, "LT", BO_LT);
    io.enumCase(value, "GT", BO_GT);
    io.enumCase(value, "LE", BO_LE);
    io.enumCase(value, "GE", BO_GE);
  }
};

template <> struct ScalarTraits<llvm::APSInt> {
  static void output(const llvm::APSInt &val, void *, llvm::raw_ostream &out) {
    val.print(out, val.isSigned());
  }
  static StringRef input(StringRef scalar, void *, llvm::APSInt &value) {
    value = llvm::APSInt(scalar);
    return StringRef();
  }
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template <> struct MappingTraits<FuncRetValToCheck> {
  static void mapping(IO &io, FuncRetValToCheck &s) {
    io.mapRequired("name", s.Name);
    io.mapRequired("relation", s.Rel);
    io.mapRequired("value", s.Val);
  }
};

} // namespace yaml
} // namespace llvm

static llvm::StringMap<FuncRetValToCheck> FuncRetValsToCheck;

namespace {
class SpecialReturnValueChecker : public Checker<check::PostCall> {
public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};
} // namespace

void SpecialReturnValueChecker::checkPostCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  if (FuncRetValsToCheck.empty())
    return;

  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  const auto RetType = FD->getReturnType();
  if (!RetType->isIntegerType() && !RetType->isPointerType())
    return;

  SmallString<256> USR;
  clang::index::generateUSRForDecl(FD, USR);

  auto ToCheck = FuncRetValsToCheck.find(USR);
  if (ToCheck == FuncRetValsToCheck.end())
    return;

  const auto RetVal = Call.getReturnValue();
  if (!RetVal.getAs<DefinedSVal>())
    return;

  auto State = C.getState();
  auto &SVB = C.getSValBuilder();
  auto &BVF = State->getBasicVals();
  auto IntType = BVF.getAPSIntType(Call.getResultType());
  auto RefInt = BVF.getValue(IntType.convert(ToCheck->second.Val));
  SVal RefVal = RetVal.getAs<NonLoc>()
                    ? static_cast<SVal>(nonloc::ConcreteInt(RefInt))
                    : static_cast<SVal>(loc::ConcreteInt(RefInt));
  const auto Relation = SVB.evalBinOp(State, ToCheck->second.Rel, RetVal,
                                      RefVal, SVB.getConditionType())
                            .getAs<DefinedOrUnknownSVal>();
  if (!Relation)
    return;

  const auto *ID = FD->getIdentifier();

  ProgramStateRef StateError, StateNormal;
  std::tie(StateError, StateNormal) = State->assume(*Relation);

  if (StateError) {
    const NoteTag *T =
        C.getNoteTag([ID, ToCheck](BugReport &BR) -> std::string {
          SmallString<256> Msg;
          llvm::raw_svector_ostream Out(Msg);

          Out << "Assuming the return value of "
              << (ID ? (ID->getName() + "()") : "the call") << " is "
              << BinaryOperator::getOpcodeStr(ToCheck->second.Rel) << " "
              << ToCheck->second.Val << " (based on call statistics)";
          return std::string(Out.str());
        });
    C.addTransition(StateError, T);
  }

  if (StateNormal) {
    const NoteTag *T =
        C.getNoteTag([ID, ToCheck](BugReport &BR) -> std::string {
          SmallString<256> Msg;
          llvm::raw_svector_ostream Out(Msg);

          Out << "Assuming the return value of "
              << (ID ? (ID->getName() + "()") : "the call") << " is "
              << BinaryOperator::getOpcodeStr(
                     BinaryOperator::negateComparisonOp(ToCheck->second.Rel))
              << " " << ToCheck->second.Val << " (based on call statistics)";
          return std::string(Out.str());
        });
    C.addTransition(StateNormal, T);
  }
}

void ento::registerSpecialReturnValueChecker(CheckerManager &Mgr) {
  const auto *checker = Mgr.registerChecker<SpecialReturnValueChecker>();

  llvm::Optional<std::vector<FuncRetValToCheck>> ToCheckVec;
  const StringRef metadataPath =
      Mgr.getAnalyzerOptions().getCheckerStringOption(checker,
                                                      "APIMetadataPath", true);

  metadata::loadYAMLData(metadataPath, "SpecialReturn.yaml", "1.0",
                         Mgr.getCurrentCheckerName(), ToCheckVec);
  for (const auto &FRVTC : *ToCheckVec) {
    FuncRetValsToCheck[FRVTC.Name] = FRVTC;
  }
}

bool ento::shouldRegisterSpecialReturnValueChecker(const CheckerManager &mgr) {
  return true;
}
