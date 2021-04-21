// RUN: %clang_analyze_cc1 -std=c++11 -analyzer-checker=core,cplusplus,ericsson.cpp.InvalidatedIteratorAccess,cplusplus,alpha.ericsson.cpp.IteratorOutOfRange,alpha.ericsson.cpp.IteratorMismatch %s 2>&1 | FileCheck %s

// XFAIL: *

// CHECK: checker cannot be enabled with analyzer option 'aggressive-binary-operation-simplification' == false
