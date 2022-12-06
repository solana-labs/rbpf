/**
 * @brief test program that creates BPF to BPF calls
 */

#include "syscalls.h"
#include "multiple_file.h"

uint64_t function_bar(uint64_t x) {
  log(__func__, sizeof(__func__));
  if (x) {
    x = function_foo(--x);
  }
  return x;
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t x = (uint64_t)*input;
  if (x) {
    x = function_foo(--x);
  }
  return x;
}
