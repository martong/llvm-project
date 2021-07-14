// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   2>&1 | FileCheck %s

// In this test we check whether the solver's symbol simplification mechanism
// is capable of reaching a fixpoint. This should be done after TWO iterations.

void clang_analyzer_printState();

void test_contradiction(int a, int b, int c, int d) {
  if (a + b + c == d)
    return;
  clang_analyzer_printState();
  // CHECK:       "disequality_info": [
  // CHECK-NEXT:    {
  // CHECK-NEXT:      "class": [ "((reg_$0<int a>) + (reg_$1<int b>)) + (reg_$2<int c>)" ],
  // CHECK-NEXT:      "disequal_to": [
  // CHECK-NEXT:        [ "reg_$3<int d>" ]]
  // CHECK-NEXT:    },
  // CHECK-NEXT:    {
  // CHECK-NEXT:      "class": [ "reg_$3<int d>" ],
  // CHECK-NEXT:      "disequal_to": [
  // CHECK-NEXT:        [ "((reg_$0<int a>) + (reg_$1<int b>)) + (reg_$2<int c>)" ]]
  // CHECK-NEXT:    }
  // CHECK-NEXT:  ],


  // Simplification starts here.
  if (b != 0)
    return;
  clang_analyzer_printState();
  // CHECK:      "disequality_info": [
  // CHECK-NEXT:   {
  // CHECK-NEXT:     "class": [ "(reg_$0<int a>) + (reg_$2<int c>)" ],
  // CHECK-NEXT:     "disequal_to": [
  // CHECK-NEXT:       [ "reg_$3<int d>" ]]
  // CHECK-NEXT:   },
  // CHECK-NEXT:   {
  // CHECK-NEXT:     "class": [ "reg_$3<int d>" ],
  // CHECK-NEXT:     "disequal_to": [
  // CHECK-NEXT:        [ "(reg_$0<int a>) + (reg_$2<int c>)" ]]
  // CHECK-NEXT:    }
  // CHECK-NEXT:  ],

  if (c != 0)
    return;
  clang_analyzer_printState();
  // CHECK:       "disequality_info": [
  // CHECK-NEXT:    {
  // CHECK-NEXT:      "class": [ "reg_$0<int a>" ],
  // CHECK-NEXT:      "disequal_to": [
  // CHECK-NEXT:        [ "reg_$3<int d>" ]]
  // CHECK-NEXT:    },
  // CHECK-NEXT:    {
  // CHECK-NEXT:      "class": [ "reg_$3<int d>" ],
  // CHECK-NEXT:      "disequal_to": [
  // CHECK-NEXT:        [ "reg_$0<int a>" ]]
  // CHECK-NEXT:    }
  // CHECK-NEXT:  ],

  // Keep the symbols and the constraints! alive.
  (void)(a * b * c * d);
  return;
}
