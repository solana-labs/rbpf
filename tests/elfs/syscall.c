/**
 * @brief Syscall function used in the BPF to BPF call test
 */
 
typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

extern void log(const char*, uint64_t);
extern void log_64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

#include "syscall.h"

uint64_t syscall_function(uint64_t x) {
  log(__func__, sizeof(__func__));
  if (x) {
    x = entrypoint_syscall_function(--x);
  }
  return x;
}
