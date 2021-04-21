// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.ericsson.concurrency.SplitCriticalSections %s -analyzer-output text -verify

#include "Inputs/system-header-simulator-cxx.h"
#include "Inputs/system-header-simulator-cxx-string.h"

void capitalizeFirstC_bad(std::string &shared_string) {
  std::mutex mtx;

  mtx.lock();
  size_t index = shared_string.find('c');
  // expected-note@-1{{Value is assigned here}}
  mtx.unlock(); // expected-note{{First critical section ends here}}

  if (index == shared_string.length()) // expected-note{{Taking false branch}} expected-note{{Assuming the condition is false}}
    return;

  mtx.lock(); // expected-note{{Second critical section begins here}}
  shared_string[index] = 'C'; // expected-warning{{Using of unreliable value in the second critical section}}
  // expected-note@-1{{Using of unreliable value in the second critical section}}
  mtx.unlock();
}

void capitalizeFirstC_good(std::string &shared_string) {
  std::mutex mtx;

  mtx.lock();
  size_t index = shared_string.find('c');

  if (index == shared_string.length())
    return;

  shared_string[index] = 'C'; // no-warning
  mtx.unlock();
}

void capitalizeFirstC_write_unlocked(std::string &shared_string) {
  std::mutex mtx;

  mtx.lock();
  size_t index = shared_string.find('c');
  mtx.unlock();

  if (index == shared_string.length())
    return;

  shared_string[index] = 'C'; // no-warning
}

void capitalizeFirstC_read_unlocked(std::string &shared_string) {
  std::mutex mtx;

  size_t index = shared_string.find('c');

  if (index == shared_string.length())
    return;

  mtx.lock();
  shared_string[index] = 'C'; // no-warning
  mtx.unlock();
}

void capitalizeFirstC_double_bad(std::string &shared_string) {
  std::mutex mtx1, mtx2;

  mtx1.lock();
  mtx2.lock();
  size_t index = shared_string.find('c');
  // expected-note@-1{{Value is assigned here}}
  mtx2.unlock(); // expected-note{{First critical section ends here}}

  if (index == shared_string.length()) // expected-note{{Taking false branch}} expected-note{{Assuming the condition is false}}
    return;

  mtx2.lock(); // expected-note{{Second critical section begins here}}
  shared_string[index] = 'C'; // expected-warning{{Using of unreliable value in the second critical section}}
  // expected-note@-1{{Using of unreliable value in the second critical section}}
  mtx2.unlock();
  mtx1.unlock();
}

void capitalizeFirstC_double_good(std::string &shared_string) {
  std::mutex mtx1, mtx2;

  mtx1.lock();
  mtx2.lock();
  size_t index = shared_string.find('c');

  if (index == shared_string.length())
    return;

  shared_string[index] = 'C';
  mtx2.unlock();
  mtx1.unlock();
}

void capitalizeFirstC_double_one_unlocked(std::string &shared_string) {
  std::mutex mtx1, mtx2;

  mtx1.lock();
  mtx2.lock();
  size_t index = shared_string.find('c');
  mtx2.unlock();

  if (index == shared_string.length())
    return;

  shared_string[index] = 'C';
  mtx1.unlock();
}

//FIXME: This seems as bad as the first one, maybe we should detect it in the
//       future.
void capitalizeFirstC_double_fewer_locks(std::string &shared_string) {
  std::mutex mtx1, mtx2;

  mtx1.lock();
  mtx2.lock();
  size_t index = shared_string.find('c');
  mtx2.unlock();
  mtx1.unlock();

  if (index == shared_string.length())
    return;

  mtx1.lock();
  shared_string[index] = 'C';
  mtx1.unlock();
}

std::mutex Mtx;

size_t locked_read(std::string &shr_str, char c) {
  Mtx.lock();
  return shr_str.find('c');
  Mtx.unlock();
}

void locked_write(std::string &shr_str, size_t idx, char c) {
  Mtx.lock();
  shr_str[idx] = c;
  Mtx.unlock();
}

void capitalizeFirstC_separate_functions(std::string &shared_string) {
  std::mutex mtx;

  size_t index = locked_read(shared_string, 'c');

  if (index == shared_string.length())
    return;

  locked_write(shared_string, index, 'C');
}
