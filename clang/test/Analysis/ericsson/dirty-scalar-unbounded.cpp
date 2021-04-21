// RUN: %clang_analyze_cc1 -std=c++11 -analyzer-checker=alpha.security.taint,alpha.ericsson.cpp.DirtyScalar -verify -analyzer-config alpha.ericsson.cpp.DirtyScalar:CriticalOnly=false -DDIRTYSCALARSTRICT=1 %s

#include "Inputs/system-header-simulator.h"
#include "Inputs/system-header-simulator-cxx.h"

typedef long off_t;

//ssize_t recv(int s, void *buf, size_t len, int flags); is missing from GenericTaintChecker
ssize_t pread(int fd, void *buf, size_t count, off_t offset);

void gets_tainted_ival(int val) {
  (void)val;
}

void gets_tainted_uval(unsigned int val) {
  (void)val;
}

int tainted_usage() {
  int size;
  scanf("%d", &size);
  char *buff = new char[size]; // expected-warning{{Tainted variable is used without proper bound checking}}
  for (int i = 0; i < size; ++i) {
#if DIRTYSCALARSTRICT
// expected-warning@-2{{Tainted variable is used without proper bound checking}}
#endif
    scanf("%d", &buff[i]);
  }
  buff[size - 1] = 0;     // expected-warning{{Tainted variable is used without proper bound checking}}
  *(buff + size - 2) = 0; // expected-warning{{Tainted variable is used without proper bound checking}}
  gets_tainted_ival(size);
#if DIRTYSCALARSTRICT
// expected-warning@-2{{Tainted variable is used without proper bound checking}}
#endif

  return 0;
}

int tainted_usage_checked() {
  int size;
  scanf("%d", &size);
  if (size < 0 || size > 255)
    return -1;
  char *buff = new char[size];     // no warning
  for (int i = 0; i < size; ++i) { // no warning
    scanf("%d", &buff[i]);         // no warning
  }
  buff[size - 1] = 0;      // no warning
  *(buff + size - 2) = 0;  // no warning
  gets_tainted_ival(size); // no warning

  unsigned int idx;
  scanf("%d", &idx);
  if (idx > 255)
    return -1;
  gets_tainted_uval(idx); // no warning

  return 0;
}

int detect_tainted(char const **messages) {
  int sock, index;
  scanf("%d", &sock);
  if (pread(sock, &index, sizeof(index), 0) != sizeof(index)) { // no warning
    return -1;
  }
  int index2 = index;
  printf("%s\n", messages[index]);  // expected-warning{{Tainted variable is used without proper bound checking}}
  printf("%s\n", messages[index2]); // expected-warning{{Tainted variable is used without proper bound checking}}

  return 0;
}

int skip_sizes_likely_used_for_table_access(char const **messages) {
  int sock;
  char byte;

  scanf("%d", &sock);
  if (pread(sock, &byte, sizeof(byte), 0) != sizeof(byte)) { // no warning
    return -1;
  }
  char byte2 = byte;
  printf("%s\n", messages[byte]);  // no warning
  printf("%s\n", messages[byte2]); // no warning

  return 0;
}

struct Dummy {
  char* dummy;
  Dummy(char* d) : dummy(d) {}
};

void check_in_place_new() {
  char* buf = new char[sizeof(Dummy)];
  Dummy* d = new (buf) Dummy(buf); // no warning
  d->~Dummy();
  delete[] buf;
}

typedef long socklen_t;
const int AF_INET = 1;
const int SOCK_RAW = 2;
const int IPPROTO_RAW = 11;
const int IPPROTO_IP = 12;
const int IP_HDRINCL = 20;
extern int socket(int domain, int type, int protocol);
extern int close(int fildes);
extern int setsockopt(int socket, int level, int option_name,
                      const void *option_value, socklen_t option_len);

void test_no_warning_for_socket() {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  int on = 1;
  int status =
      setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)); // no warning

  close(sock); // no warning
}
