#include "syscalls.h"

extern uint64_t entrypoint(const uint8_t *input) {
  log("foo\n", 4);

  return 0;
}
