
def Ericsson : Package<"ericsson">;

def Cpp : Package<"cpp">, ParentPackage<Ericsson>;

def CppSTL : Package<"stl">, ParentPackage<Cpp>;

def CppStyle : Package<"style">, ParentPackage<Cpp>;

def PreCpp11 : Package<"precpp11">, ParentPackage<Ericsson>;

def PreCpp11STL : Package<"stl">, ParentPackage<PreCpp11>;

def LinuxKernelStyle : Package<"linuxkernelstyle">, ParentPackage<Ericsson>;

def MisraC : Package<"misrac">, ParentPackage<Ericsson>;

def TSP : Package<"tsp">, ParentPackage<Ericsson>;

def MTAS : Package<"mtas">, ParentPackage<Ericsson>;

// def Alpha : Package<"alpha">;

def AlphaEricsson : Package<"ericsson">, ParentPackage<Alpha>;

def AlphaCpp : Package<"cpp">, ParentPackage<AlphaEricsson>;

def AlphaCppSTL : Package<"stl">, ParentPackage<AlphaCpp>;

def ConcurrencyAlpha : Package<"concurrency">, ParentPackage<AlphaEricsson>;

def AlphaStatisticsBased : Package<"statisticsbased">, ParentPackage<AlphaEricsson>,
  PackageOptions<[
    CmdLineOption<String,
                  "APIMetadataPath",
                  "Directory where statistics are collected.",
                  "",
                  Released>
  ]>;

def AlphaStatisticsCollector : Package<"statisticscollector">, ParentPackage<AlphaEricsson>, Hidden;

let ParentPackage = Cpp in {

def IteratorModelling : Checker<"IteratorModelling">,
  HelpText<"Models iterators of C++ containers">,
  Documentation<NotDocumented>,
  Hidden;

def InvalidatedIteratorAccessChecker : Checker<"InvalidatedIteratorAccess">,
  HelpText<"Checks for accesses of invalidated iterators.">,
  Dependencies<[IteratorModelling]>,
  Documentation<NotDocumented>;

def OStreamFormatChecker : Checker<"OStreamFormat">,
  HelpText<"Check ostream objects for forgotten format modifications.">,
  Documentation<NotDocumented>;

def RaiiMisuseChecker : Checker<"RaiiMisuse">,
  HelpText<"Discover resources allocated in ctor but not released in dtor.">,
  Documentation<NotDocumented>;

def MisuseEnumAsConditionChecker : Checker<"MisuseEnumAsCondition">,
  HelpText<"Check invalid use of enum like boolean.">,
  Documentation<NotDocumented>;

def PredWithStateChecker : Checker<"PredWithState">,
  HelpText<"Predicates should not have states.">,
  Documentation<NotDocumented>;

}

let ParentPackage = CppSTL in {

def PolymorphContainerChecker : Checker<"PolymorphContainer">,
  HelpText<"Finds plymorphic use of STL containers.">,
  Documentation<NotDocumented>;

def ContainerOfAutoptrChecker : Checker<"ContainerOfAutoptr">,
  HelpText<"Finds instances where a container with std::AutoPtr items is used.">,
  Documentation<NotDocumented>;

}

let ParentPackage = CppStyle in {

def ReduceScopeChecker : Checker<"ReduceScope">,
  HelpText<"Determines if a scope of a variable can be decreased.">,
  Documentation<NotDocumented>;

def LargeObjectPassedChecker : Checker<"LargeObjectPassed">,
  HelpText<"Check if huge objects are passed by value.">,
  CheckerOptions<[
    CmdLineOption<Integer,
                  "SizeThreshold",
                  "The lower size threshold in ***BITS***.",
                  "1024",
                  Released>
  ]>,
  Documentation<NotDocumented>;

def MissingConstChecker : Checker<"MissingConst">,
  HelpText<"Determines if a variable should be const.">,
  CheckerOptions<[
    CmdLineOption<Boolean,
                  "CheckValueParams",
                  "Also check function parameters.",
                  "false",
                  Released>
  ]>,
  Documentation<NotDocumented>;

}

let ParentPackage = PreCpp11STL in {

def AllocWithStateChecker : Checker<"AllocWithState">,
  HelpText<"Finds stateful allocators.">,
  Documentation<NotDocumented>;

def UnaryFunctorTypeMismatchChecker : Checker<"UnaryFunctorTypeMismatch">,
  HelpText<"Detects std::UnaryFunction template parameter type mismatches.">,
  Documentation<NotDocumented>;

def BinFunctorTypeMismatchChecker : Checker<"BinFunctorTypeMismatch">,
  HelpText<"Detects std::BinaryFunction template parameter type mismatches.">,
  Documentation<NotDocumented>;

}

let ParentPackage = LinuxKernelStyle in {

def PointerDeclChecker : Checker<"PointerDecl">,
  HelpText<"When declaring pointer data or a function that returns a pointer type, the preferred use of * is adjacent to the data name or function name and not adjacent to the type name.">,
  Documentation<NotDocumented>;

}

let ParentPackage = MisraC in {

def ExternalArrayWithUnknownSizeChecker : Checker<"ExternalArrayWithUnknownSize">,
  HelpText<"MISRA-C 8.12: Declaration of an external array with unknown size">,
  Documentation<NotDocumented>;

def FunctionsWithNoParamChecker : Checker<"FunctionsWithNoParam">,
  HelpText<"MISRA-C 16.5: Functions with no parameters shall be declared and defined with void parameter list.">,
  Documentation<NotDocumented>;

def AssignmentInConditionChecker : Checker<"AssignmentInCondition">,
  HelpText<"MISRA-C 13.1: Assignment operator is used in a condition">,
  Documentation<NotDocumented>;

def SwitchDefaultBranchChecker : Checker<"SwitchDefaultBranch">,
  HelpText<"MISRA-C 15.3 Always add a default branch to switch statement.">,
  Documentation<NotDocumented>;

}

let ParentPackage = TSP in {

def TspBuiltinTypesChecker : Checker<"TspBuiltinTypes">,
  HelpText<"Detects usage of pointer comparison.">,
  Documentation<NotDocumented>;

def DbnTransactionManagementChecker : Checker<"DbnTransactionManagement">,
  HelpText<"Detects DBN transaction mismanagement issues.">,
  Documentation<NotDocumented>;

}

let ParentPackage = MTAS in {

def SerializeVersionChecker : Checker<"SerializeVersion">,
  HelpText<"MTAS StartRestart rule 20.">,
  Documentation<NotDocumented>;

def DialogueSetupCreateChecker : Checker<"DialogueSetupCreate">,
  HelpText<"Find instances of Dialogue Setup Classes, which were created in wrong method.">,
  Documentation<NotDocumented>;

def IllegalTracingChecker : Checker<"IllegalTracing">,
  HelpText<"Find illegal tracing methods.">,
  Documentation<NotDocumented>;

def EpctParametersChecker : Checker<"EpctParameters">,
  HelpText<"Finds deprecated epct parameter uses.">,
  Documentation<NotDocumented>;

def SerializeWithoutObserverChecker : Checker<"SerializeWithoutObserver">,
  HelpText<"Finds classes that support serialisation but not inherit from ISerializerObserver.">,
  Documentation<NotDocumented>;

def LicenseManagementChecker : Checker<"LicenseManagement">,
  HelpText<"TSPLicenseManagerBackend should be used instead of raw license management.">,
  Documentation<NotDocumented>;

def DbnDelayAfterRetryChecker : Checker<"DbnDelayAfterRetry">,
  HelpText<"Detects when a DBN transaction is retried without delay.">,
  Documentation<NotDocumented>;

def MtasConventionsChecker : Checker<"MtasConventions">,
  HelpText<"Validates the code against MTAS coding conventions.">,
  Documentation<NotDocumented>;

}

let ParentPackage = AlphaCpp in {

def BitwiseShiftChecker : Checker<"BitwiseShift">,
  HelpText<"Finds cases where bitwise shift operation causes undefined behaviour.">,
  Documentation<NotDocumented>;

def DirtyScalarChecker : Checker<"DirtyScalar">,
  HelpText<"Warn on using tainted integers without proper bound check.">,
  CheckerOptions<[
    CmdLineOption<Boolean,
                  "CriticalOnly",
                  "Only check usage of tainted integers in the following \"critical\" functions: memcpy(), malloc(), calloc(), strcpy(), strncpy() and memmove()",
                  "true",
                  Released>
  ]>,
  Documentation<NotDocumented>;

def InvariablePtrBranchChecker : Checker<"InvariablePtrBranch">,
  HelpText<"Discover redundant nullpointer checks.">,
  Documentation<NotDocumented>;

def IteratorOutOfRangeChecker : Checker<"IteratorOutOfRange">,
  HelpText<"Checks for iterators accessed outside their range.">,
  Dependencies<[IteratorModelling]>,
  CheckerOptions<[
    CmdLineOption<Boolean,
                  "AggressiveEraseModeling",
                  "Enables exploration of the past-the-end branch for the "
                  "return value of the erase() method of containers.",
                  "false",
                  Released>
  ]>,
  Documentation<NotDocumented>;

def IteratorMismatchChecker : Checker<"IteratorMismatch">,
  HelpText<"Checks for container-iterator and iterator-iterator mismatches.">,
  Dependencies<[IteratorModelling]>,
  Documentation<NotDocumented>;

}

let ParentPackage = AlphaStatisticsBased in {

def UncheckedReturnValueChecker : Checker<"UncheckedReturnValue">,
  HelpText<"Checks whether the return value of functions listed in UncheckedReturn.yaml are checked upon calls.">,
  Documentation<NotDocumented>;

def SpecialReturnValueChecker : Checker<"SpecialReturnValue">,
  HelpText<"Tests whether the return value of funcions listed in SpecialReturn.yaml are checked against a special value (relation and value also in the yaml).">,
  Documentation<NotDocumented>;

}

let ParentPackage = AlphaStatisticsCollector in {

def ReturnValueCheckStatisticsCollector : Checker<"ReturnValueCheck">,
  HelpText<"Collects statistics whether the return value of a function is checked">,
  Documentation<NotDocumented>;

def SpecialReturnValueStatisticsCollector : Checker<"SpecialReturnValue">,
  HelpText<"Collects statistics whether the return value of a function is compared to a special value (negative integer or null pointer)">,
  Documentation<NotDocumented>;

}

let ParentPackage = ConcurrencyAlpha in {

def SplitCriticalSectionsChecker : Checker<"SplitCriticalSections">,
  HelpText<"Detects usage of variables in a critical section which were assigned in a previous one.">,
  Documentation<NotDocumented>;

}

let ParentPackage = AlphaEricsson in {

def MemsizeParamOverloadChecker : Checker<"MemsizeParamOverload">,
  HelpText<"Find functions of which different overloads are invoked in 32/64 bit environments.">,
  CheckerOptions<[
    CmdLineOption<Boolean,
                  "AnyTypedefType",
                  "Reports on any typedef type argument in the function call assuming that its underlying type may change, even if it is not a memsize type currently",
                  "false",
                  Released>
  ]>,
  Documentation<NotDocumented>;

def NegativeArrayIndexChecker : Checker<"NegativeArrayIndex">,
  HelpText<"Checks for cases, where negative index values are used for indexing arrays, which indicate possible overflow.">,
  Documentation<NotDocumented>;

def NonPortableUnionChecker : Checker<"NonPortableUnion">,
  HelpText<"Warns for union definitions that are prone to incompatibilities when compiled to 64 bits architecture instead of 32 bits.">,
  Documentation<NotDocumented>;

def SufficientSizeArrayIndexingChecker : Checker<"SufficientSizeArrayIndexing">,
  HelpText<"Checks for indexing of an array, where the type of the index is not sufficient to cover the index range of the whole array.">,
  Documentation<NotDocumented>;

}
