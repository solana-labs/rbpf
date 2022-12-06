/**
 * @brief test program that generates BPF PC relative call instructions
 */

#include "syscalls.h"

uint64_t __attribute__ ((noinline)) function_foo(uint64_t x) {
  log(__func__, sizeof(__func__));
  return x + 1;
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t x = (uint64_t)*input;
  log(__func__, sizeof(__func__));
  x = function_foo(x);
  return x;
}

