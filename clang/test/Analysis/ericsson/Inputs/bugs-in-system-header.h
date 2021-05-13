// Bugs detected in a system header should not be reported.
#pragma clang system_header

void test_missing_const() {
  int x = 7;
  (void)x;
}

#define TEST_MISSING_CONST(X) int __x = X

int __global_int;
#define sys_func_with_assign(X) ( __global_int = X + 1 )
