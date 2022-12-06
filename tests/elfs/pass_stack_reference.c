/**
 * @brief test program that generates BPF PC relative call instructions
 */

typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

void __attribute__ ((noinline)) function_4(uint64_t* x) {
  *x = 42;
}

void __attribute__ ((noinline)) function_3(uint64_t* x) {
  uint64_t array[256];
  function_4(&array[128]);
  *x = array[128];
}

void __attribute__ ((noinline)) function_2(uint64_t* x) {
  uint64_t array[256];
  function_3(&array[128]);
  *x = array[128];
}

void __attribute__ ((noinline)) function_1(uint64_t* x) {
  uint64_t array[256];
  function_2(&array[128]);
  *x = array[128];
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t array[256];
  function_1(&array[128]);
  return array[128];
}

