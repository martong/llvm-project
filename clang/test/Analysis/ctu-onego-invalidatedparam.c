// RUN: rm -rf %t && mkdir %t
// RUN: mkdir -p %t/ctudir
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -emit-pch -o %t/ctudir/ctu-onego-invalidatedparam-other.c.ast %S/Inputs/ctu-onego-invalidatedparam-other.c
// RUN: cp %S/Inputs/ctu-onego-invalidatedparam-other.c.externalDefMap.ast-dump.txt %t/ctudir/externalDefMap.txt

// RUN: %clang_analyze_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.unix.cstring.OutOfBounds \
// RUN:   -analyzer-config eagerly-assume=true \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config ctu-dir=%t/ctudir \
// RUN:   -analyzer-config display-ctu-progress=true \
// RUN:   -Wno-pointer-sign \
// RUN:   -verify=ctu %s
// ctu-no-diagnostics
// RUN: %clang_analyze_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.unix.cstring.OutOfBounds \
// RUN:   -analyzer-config eagerly-assume=true \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config ctu-dir=%t/ctudir \
// RUN:   -analyzer-config display-ctu-progress=true \
// RUN:   %s 2>&1 | FileCheck %s
// CHECK: CTU loaded AST file

// RUN: %clang_analyze_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.unix.cstring.OutOfBounds \
// RUN:   -analyzer-config eagerly-assume=true \
// RUN:   -Wno-pointer-sign \
// RUN:   -verify=nonctu %s


typedef struct evp_md_ctx_st a;
int b(a *, const int*);
int c();
int f();
int k_bytes();
struct evp_md_st;
struct evp_md_st *EVP_MD_fetch();
int e();
void *memcpy(void *, const void *, unsigned long);
int BN_generate_dsa_nonce() {
  c();
  char digest[64];
  unsigned done, todo, d = f() + 8;
  k_bytes();
  EVP_MD_fetch();
  done = 0;
  for (;;) {
    b((a*)c, &done) || e(digest);
    todo = d - done;
    if (todo > 4)
      todo = 64;
    // nonctu-warning@+1{{alpha.unix.cstring.OutOfBounds}}
    memcpy((char*)k_bytes + done, digest, todo);
    done = todo;
  }
}
