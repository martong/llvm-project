// RUN: rm -rf %t && mkdir %t
// RUN: mkdir -p %t/ctudir
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -emit-pch -o %t/ctudir/ctu-onego-invalidatedparam-other.c.ast %S/Inputs/ctu-onego-invalidatedparam-other.c
// RUN: cp %S/Inputs/ctu-onego-invalidatedparam-other.c.externalDefMap.ast-dump.txt %t/ctudir/externalDefMap.txt

// RUN: %clang_analyze_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config ctu-dir=%t/ctudir \
// RUN:   -analyzer-config display-ctu-progress=true \
// RUN:   -Wno-pointer-sign \
// RUN:   -verify=ctu %s
// RUN: %clang_analyze_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config ctu-dir=%t/ctudir \
// RUN:   -analyzer-config display-ctu-progress=true \
// RUN:   %s 2>&1 | FileCheck %s
// CHECK: CTU loaded AST file

// RUN: %clang_analyze_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -Wno-pointer-sign \
// RUN:   -verify=nonctu %s

void clang_analyzer_eval();

struct evp_md_ctx_st;
int b(struct evp_md_ctx_st *, const int*);
struct evp_md_ctx_st *EVP_MD_fetch();
int BN_generate_dsa_nonce(struct evp_md_ctx_st *X) {
  unsigned done = 0;
  EVP_MD_fetch();
  // FIXME Below both ctu and nonctu should give the same warning. The reason
  // for the difference is that during ctu we import evp_md_ctx_st which has a
  // function pointer as a member, thus that is considered as a callback, thus
  // all arguments of the below call will be invalided (regardless of being
  // `const int*`).
  b(X, &done);
  // nonctu-warning@+2{{TRUE}}
  // ctu-warning@+1{{UNKNOWN}}
  clang_analyzer_eval(done == 0);
  return 0;
}
