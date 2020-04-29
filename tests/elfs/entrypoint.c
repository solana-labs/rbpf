/**
 * @brief test program that creates BPF to BPF calls
 */

typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

extern void log(const char*, uint64_t);
extern void log_64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

#include "syscall.h"

uint64_t entrypoint_syscall_function(uint64_t x) {
  log(__func__, sizeof(__func__));
  if (x) {
    x = syscall_function(--x);
  }
  return x;
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t x = (uint64_t)*input;
  if (x) {
    x = syscall_function(--x);
  }
  return x;
}
