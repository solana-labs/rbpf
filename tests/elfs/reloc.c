/**
 * @brief a program to test R_BPF_64_64 relocation handling
 */

typedef unsigned long int uint64_t;
typedef unsigned char uint8_t;

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t (*ptr)(const uint8_t *) = entrypoint;
  return (uint64_t) ptr;
}
