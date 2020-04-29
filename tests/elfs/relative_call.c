/**
 * @brief test program that generates BPF PC relative call instructions
 */

typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

extern void log(const char*, uint64_t);

uint64_t __attribute__ ((noinline)) syscall(uint64_t x) {
  log(__func__, sizeof(__func__));
  return x + 1;
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t x = (uint64_t)*input;
  log(__func__, sizeof(__func__));
  x = syscall(x);
  return x;
}

