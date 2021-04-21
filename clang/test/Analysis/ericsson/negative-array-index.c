// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.ericsson.NegativeArrayIndex -Wno-everything -verify %s

#include "Inputs/system-header-simulator.h"

// Fetch the element in the array
// with "int" index. Might cause false result
ptrdiff_t get_element_wrong(int *array, int Index) {
  intptr_t element = (intptr_t)(&(array[Index])); // expected-warning {{Array is indexed with a negative value. Possible integer overflow}}
  return element - (ptrdiff_t)array;
}

// Fetch the element in the array
// with "size_t" index, correct way
ptrdiff_t get_element_correct(int *array, size_t Index) {
  intptr_t element = (intptr_t)(&(array[Index]));
  return element - (ptrdiff_t)array;
}

void execute_array_index() {
  printf("***********************************************'\n");
  printf("Execute the issue of array index --- Start!\n\n");
  size_t i = 0x7FFFFFFF;
  int j = 0x7FFFFFFF;
  size_t loop_counter = 0;
  int *array = NULL;

  while (loop_counter < 2) {
    printf("loop--------------------------------------------\n");
    printf("The element should be accessed is No. 0x%zx \n", i);
    printf("The right element been accessed is No. 0x%tx \n",
           get_element_correct(array, i));
    printf("The wrong element been accessed is No. 0x%tx \n",
           get_element_wrong(array, j));
    i++;
    j++;
    loop_counter++;
  }
  printf("\nExecute the issue of array index --- End!\n");
  printf("***********************************************'\n");
}

int returns_random_int();

void literal_index() {
  char array[INT32_MAX];
  array[-3]; // no warning on integer literals
}

void expression_index() {
  char array[INT32_MAX];
  array[123-124]; // no warning on integer literals
}

void unknown_function_result_index() {
  char array[INT32_MAX];
  array[returns_random_int()];  // result of function call could be anything, should not warn
}

void overflowed_index() {
  char array[INT32_MAX];
  array[INT32_MAX + 1]; // no warning on integer literals
}

void unknown_expression_index() {
  char array[INT32_MAX];
  array[returns_random_int() + INT32_MAX]; // result of the expression is not known, should not warn
}

// Should not check pointer arithmetic.
void constant_subtraction_pointer_arithmetic() {
  char array[32] = {0};
  char c = *(array - 12); // no warning should be emitted on pointer arithmetic
}

void unknown_expression_pointer_arithmetic() {
  char array[32] = {0};
  char c = *(array - returns_random_int()); // no warning should be emitted on pointer arithmetic
}
