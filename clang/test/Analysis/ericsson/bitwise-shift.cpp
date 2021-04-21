// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.cpp.BitwiseShift -verify %s

/*
    Here I've tested the scenario where the checker has no
    information about any of the operators. Therefore it
    can't say anything about the correctness of the operation.
    There should be no warning.
*/
int NoInformation(int left, int right) { return left << (right + 2 + 1 + 1); }
int NoInformation_2(int left, int right) { return (left + 2 + 1 + 1) >> (right); }

/*
    Here I've tested the scenario where the right operand
    value is bigger than the left operand type size. Therefore
    the checker should give a warning.
*/
int LeftShiftOverflow(int left, int right) {
  if (right < 32)
    return 0;

  //right >= 32
  //On this branch we have an undefined behaviour because of bit overflow.
  //(They get discarded.)
  return left << (right); // expected-warning{{Left shift right operand is greater than left type capacity}}
}

int RightShiftOverflow(int left, int right) {
  if (right < 32)
    return 0;

  //right >= 32
  //On this branch we have an undefined behaviour because of bit overflow.
  //(They get discarded.)
  return left >> (right); // expected-warning{{Right shift right operand is greater than left type capacity}}
}

/*
    Here I've tested the scenario where the right operand
    value is bigger than the left operand type size. Therefore
    the checker should give a warning.
*/
int LeftShiftOverflow_1(int left, int right) {
  right = 29;

  //On this branch we have an undefined behaviour because of bit overflow.
  //(They get discarded.)
  return left << (right + 2 + 1); // expected-warning{{Left shift right operand is greater than left type capacity}}
}

long long LeftShiftOverflow_2(long long left, long right) {
  right = 64;

  //On this branch we have an undefined behaviour because of bit overflow.
  //(They get discarded.)
  return left << (right); // expected-warning{{Left shift right operand is greater than left type capacity}}
}

/*
    Here I've tested the scenario where the right operand
    value is negative. In both shift direction cases the
    checker should give a warning.
*/
int LeftShift_RightOperand_IsNegative(int left, int right) {
  if (right >= 0)
    return 0;

  //Right < 0
  //Here we have an undefined behaviour, because right is negative.
  return left << (right); // expected-warning{{Right operand is negative in left shift}}
}

int RightShift_RightOperand_IsNegative(int left, int right) {
  if (right >= 0)
    return 0;

  //Right < 0
  //Here we have an undefined behaviour, because right is negative.
  return left >> (right); // expected-warning{{Right operand is negative in right shift}}
}

int RightShift_LeftOperand_IsNegative(int left, int right) {
  if (left >= 0)
    return 0;
  return left >> right; // expected-warning{{Left operand is negative in right shift}}
}

int LeftShift_LeftOperand_IsNegative(int left, int right) {
  if (left >= 0)
     return 0;
  return left << right; // expected-warning{{Left operand is negative in left shift}}
}

// Negative test of LeftShift, should not fail.
int LeftShift_test(int left, int right) {
  if (left < 0 || right < 0)
    return 0;
  return (left << right);
}

// Negative test of RightShift, should not fail.
int RightShift_test(int left, int right) {
  if (left < 0 || right < 0)
    return 0;
  return (left >> right);
}

/*
    Here I've tested the scenario where the right operand
    value is smaller than the left hand type size, but the shift
    will push out a bit from the signed type capacity.
    The new number is still representable in the unsigned type.
    Notice that we are in a C++ file. In the C++ standard the new int
    has to be representable in the corresponding unsigned type.
*/
int LeftShift_() {
  int left = 1;
  int right = 31;

  //Legal move in C++ !
  //( Left new value is representable in unsigned type )
  return left << (right); // no-warning
}

/*
    Here I've tested the scenario where the right operand
    value is smaller than the left hand type size, but the shift
    will push out a bit from the unsigned type capacity.
*/
int LeftShift_Bitoverflow_2() {
  //00...0010100 ( Data is represented on a 5 digit long binary number.)
  int left = 20;
  int right = 27; //Shift it by 28 bits.

  /*
        Type size is 32. 5+27+1 is 33 so one bit will get discarded
        and the number may change sign.
    */
  return left << (right + 1); // expected-warning{{Bit overflow in left shift}}
}

int LeftShift_Bitoverflow_3(int right) {
  //00...0010100 ( Data is represented on a 5 digit long binary number.)
  int left = 20;

  if (right > 27) {
    //If right is 28 that means 5+28=33 and that is bigger than 32
    return left << right; // expected-warning{{Bit overflow in left shift}}
  }
  return 0;
}
