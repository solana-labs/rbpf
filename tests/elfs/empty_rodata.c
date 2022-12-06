/**
 * @brief test program
 */

#include "syscalls.h"

extern uint64_t entrypoint(const uint8_t *input) {
  log_64(1, 2, 3, 4, 5);
  return 0;
}
