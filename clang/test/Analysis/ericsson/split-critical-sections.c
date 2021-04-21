// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.ericsson.concurrency.SplitCriticalSections -Wno-implicit-function-declaration %s -analyzer-output text -verify

#include "Inputs/system-header-simulator.h"
#include "Inputs/system-header-simulator-for-pthread-lock.h"

void capitalizeFirstC_bad(char *shared_string) {
  pthread_mutex_t mutex;

  pthread_mutex_lock(&mutex);
  char *firstC = strchr(shared_string, 'c');
  // expected-note@-1{{Value is assigned here}}
  pthread_mutex_unlock(&mutex);
  // expected-note@-1{{First critical section ends here}}

  if (!firstC) // expected-note{{Taking false branch}}
    // expected-note@-1{{Assuming 'firstC' is non-null}}
    return;

  pthread_mutex_lock(&mutex);
  // expected-note@-1{{Second critical section begins here}}
  *firstC = 'C'; // expected-warning{{Using of unreliable value in the second critical section}}
  // expected-note@-1{{Using of unreliable value in the second critical section}}
  pthread_mutex_unlock(&mutex);
}

void capitalizeFirstC_good(char *shared_string) {
  pthread_mutex_t mutex;

  pthread_mutex_lock(&mutex);
  char *firstC = strchr(shared_string, 'c');

  if (!firstC)
    return;

  *firstC = 'C'; // no-warning
  pthread_mutex_unlock(&mutex);
}

void capitalizeFirstC_write_unlocked(char *shared_string) {
  pthread_mutex_t mutex;

  pthread_mutex_lock(&mutex);
  char *firstC = strchr(shared_string, 'c');
  pthread_mutex_unlock(&mutex);

  if (!firstC)
    return;

  *firstC = 'C'; // no-warning
}

void capitalizeFirstC_read_unlocked(char *shared_string) {
  pthread_mutex_t mutex;

  char *firstC = strchr(shared_string, 'c');

  if (!firstC)
    return;

  pthread_mutex_lock(&mutex);
  *firstC = 'C'; // no-warning
  pthread_mutex_unlock(&mutex);
}

void capitalizeFirstC_double_bad(char *shared_string) {
  pthread_mutex_t mutex1, mutex2;

  pthread_mutex_lock(&mutex1);
  pthread_mutex_lock(&mutex2);
  char *firstC = strchr(shared_string, 'c');
  // expected-note@-1{{Value is assigned here}}
  pthread_mutex_unlock(&mutex2);
  // expected-note@-1{{First critical section ends here}}

  if (!firstC) // expected-note{{Taking false branch}}
    // expected-note@-1{{Assuming 'firstC' is non-null}}
    return;

  pthread_mutex_lock(&mutex2);
  // expected-note@-1{{Second critical section begins here}}
  *firstC = 'C'; // expected-warning{{Using of unreliable value in the second critical section}}
  // expected-note@-1{{Using of unreliable value in the second critical section}}
  pthread_mutex_unlock(&mutex2);
  pthread_mutex_unlock(&mutex1);
}

void capitalizeFirstC_double_good(char *shared_string) {
  pthread_mutex_t mutex1, mutex2;

  pthread_mutex_lock(&mutex1);
  pthread_mutex_lock(&mutex2);
  char *firstC = strchr(shared_string, 'c');

  if (!firstC)
    return;

  *firstC = 'C'; // no-warning
  pthread_mutex_unlock(&mutex2);
  pthread_mutex_unlock(&mutex1);
}

void capitalizeFirstC_double_one_unlocked(char *shared_string) {
  pthread_mutex_t mutex1, mutex2;

  pthread_mutex_lock(&mutex1);
  pthread_mutex_lock(&mutex2);
  char *firstC = strchr(shared_string, 'c');

  if (!firstC)
    return;

  *firstC = 'C'; // no-warning
  pthread_mutex_unlock(&mutex2);
  pthread_mutex_unlock(&mutex1);
}

//FIXME: This seems as bad as the first one, maybe we should detect it in the
//       future.
void capitalizeFirstC_double_fewer_locks(char *shared_string) {
  pthread_mutex_t mutex1, mutex2;

  pthread_mutex_lock(&mutex1);
  pthread_mutex_lock(&mutex2);
  char *firstC = strchr(shared_string, 'c');
  pthread_mutex_unlock(&mutex2);
  pthread_mutex_unlock(&mutex1);

  if (!firstC)
    return;

  pthread_mutex_lock(&mutex1);
  *firstC = 'C'; // no-warning
  pthread_mutex_unlock(&mutex1);
}

pthread_mutex_t Mutex;

char *locked_read(const char *shr_str, char c) {
  pthread_mutex_lock(&Mutex);
  return strchr(shr_str, 'c');
  pthread_mutex_unlock(&Mutex);
}

void locked_write(char *shr_str, char c) {
  pthread_mutex_lock(&Mutex);
  *shr_str = c;
  pthread_mutex_unlock(&Mutex);
}

void capitalizeFirstC_separate_functions(char *shared_string) {
  pthread_mutex_t mutex1, mutex2;

  char *firstC = locked_read(shared_string, 'c');

  if (!firstC)
    return;

  locked_write(firstC, 'C'); // no-warning
}

pthread_mutex_t r, g;
unsigned int b = 0;

void readers_writers_reader() {
  pthread_mutex_lock(&r);
  ++ b;
  if (b == 1) {
    pthread_mutex_lock(&g);
  }
  pthread_mutex_unlock(&r);

  /* READ */

  pthread_mutex_lock(&r);
  -- b; // no-warning
  if (b == 0) {
    pthread_mutex_unlock(&g);
  }
  pthread_mutex_unlock(&r);
}
