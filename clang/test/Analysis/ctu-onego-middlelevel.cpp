// RUN: rm -rf %t && mkdir %t
// RUN: mkdir -p %t/ctudir
// RUN: %clang_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -emit-pch -o %t/ctudir/ctu-onego-middlelevel-other.cpp.ast %S/Inputs/ctu-onego-middlelevel-other.cpp
// RUN: cp %S/Inputs/ctu-onego-middlelevel-other.cpp.externalDefMap.ast-dump.txt %t/ctudir/externalDefMap.txt

// RUN: %clang_analyze_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.security.ArrayBoundV2 \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config ctu-dir=%t/ctudir \
// RUN:   -analyzer-config display-ctu-progress=true \
// RUN:   -analyzer-display-progress \
// RUN:   -verify=ctu %s
// RUN: %clang_analyze_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.security.ArrayBoundV2 \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config ctu-dir=%t/ctudir \
// RUN:   -analyzer-config display-ctu-progress=true \
// RUN:   -analyzer-display-progress %s 2>&1 | FileCheck --check-prefix=ORDER-CHECK %s
// ORDER-CHECK: ANALYZE (Path,  Inline_Regular):{{.*}}funEee()CTU loaded AST file
// ORDER-CHECK: ANALYZE (Path,  Inline_Regular):{{.*}}funAaa()

// RUN: %clang_analyze_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.security.ArrayBoundV2 \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-display-progress \
// RUN:   -verify=nonctu %s

int compareString(char *, char *);
unsigned long stringLen(char *);

unsigned long stringLen(char *a) {
  char *pszTmp = a;
  // nonctu-warning@+2{{ArrayBoundV2}}
  // ctu-warning@+1{{ArrayBoundV2}}
  while (*pszTmp++)
    ;
  return 0;
}

void funAaa() {
  char *b = new char;
  stringLen(b);
}

char *d;
void funEee() {
  compareString(0, d);
  return;
  funAaa();
}

