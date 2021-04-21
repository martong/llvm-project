// Bugs detected in a system header should not be reported.
#pragma clang system_header

void test_missing_const() {
  int x = 7;
  (void)x;
}

#define TEST_MISSING_CONST(X) int __x = X
