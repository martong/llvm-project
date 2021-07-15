// RUN: %clang_analyze_cc1 -verify %s \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false

// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   2>&1 | FileCheck %s

void clang_analyzer_eval(int);
void clang_analyzer_warnIfReached();
void clang_analyzer_printState();

void testIntersection(int a, int b, int c) {
  if (a < 42 && b > 15 && c >= 25 && c <= 30) {
    if (a != b)
      return;

    clang_analyzer_eval(a > 15);  // expected-warning{{TRUE}}
    clang_analyzer_eval(b < 42);  // expected-warning{{TRUE}}
    clang_analyzer_eval(a <= 30); // expected-warning{{UNKNOWN}}

    clang_analyzer_printState(); // At this point a, b, c are alive
    // CHECK:      "constraints": [
    // CHECK-NEXT:   { "symbol": "reg_$0<int a>", "range": "{ [16, 41] }" },
    // CHECK-NEXT:   { "symbol": "reg_$1<int b>", "range": "{ [16, 41] }" },
    // CHECK-NEXT:   { "symbol": "reg_$2<int c>", "range": "{ [25, 30] }" },
    // CHECK-NEXT:   { "symbol": "(reg_$0<int a>) != (reg_$1<int b>)", "range": "{ [0, 0] }" }
    // CHECK-NEXT: ],
    // CHECK-NEXT: "equivalence_classes": [
    // CHECK-NEXT:   [ "reg_$0<int a>", "reg_$1<int b>" ]
    // CHECK-NEXT: ],
    // CHECK-NEXT: "disequality_info": null,

    if (c == b) {
      // Also, it should be noted that c is dead at this point, but the
      // constraint initially associated with c is still around.
      clang_analyzer_printState(); // a, b are alive
      // CHECK:      "constraints": [
      // CHECK-NEXT:   { "symbol": "reg_$0<int a>", "range": "{ [25, 30] }" },
      // CHECK-NEXT:   { "symbol": "reg_$1<int b>", "range": "{ [25, 30] }" },
      // CHECK-NEXT:   { "symbol": "(reg_$0<int a>) != (reg_$1<int b>)", "range": "{ [0, 0] }" }
      // CHECK-NEXT: ],
      // CHECK-NEXT: "equivalence_classes": [
      // CHECK-NEXT:   [ "reg_$0<int a>", "reg_$1<int b>" ]
      // CHECK-NEXT: ],
      // CHECK-NEXT: "disequality_info": null,
      clang_analyzer_eval(a >= 25 && a <= 30); // expected-warning{{TRUE}}

      clang_analyzer_printState(); // only b is alive
      // CHECK:       "constraints": [
      // CHECK-NEXT:    { "symbol": "reg_$1<int b>", "range": "{ [25, 30] }" }
      // CHECK-NEXT:  ],
      // CHECK-NEXT:  "equivalence_classes": null,
      // CHECK-NEXT:  "disequality_info": null,
      clang_analyzer_eval(b >= 25 && b <= 30); // expected-warning{{TRUE}}

      clang_analyzer_printState(); // all died
      // CHECK:       "constraints": null,
      // CHECK-NEXT:  "equivalence_classes": null,
      // CHECK-NEXT:  "disequality_info": null,
    }
  }
}
