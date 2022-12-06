/**
 * @brief Syscall function used in the BPF to BPF call test
 */

#include "syscalls.h"
#include "multiple_file.h"

uint64_t function_foo(uint64_t x) {
  log(__func__, sizeof(__func__));
  if (x) {
    x = function_bar(--x);
  }
  return x;
}
