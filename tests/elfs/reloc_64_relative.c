/**
 * @brief a program to test R_BPF_64_RELATIVE relocation handling
 */

typedef unsigned long int uint64_t;
typedef unsigned char uint8_t;

extern uint64_t entrypoint(const uint8_t *input) {
  return (uint64_t) __func__;
}
