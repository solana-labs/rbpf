/**
 * @brief test program that generates BPF PC relative call instructions
 */

typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

extern void log(const char*);
extern void log_64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

void __attribute__ ((noinline)) helper_4(uint64_t* x) {
  *x = 42;
}

void __attribute__ ((noinline)) helper_3(uint64_t* x) {
  uint64_t array[256];
  helper_4(&array[128]);
  *x = array[128];
}

void __attribute__ ((noinline)) helper_2(uint64_t* x) {
  uint64_t array[256];
  helper_3(&array[128]);
  *x = array[128];
}

void __attribute__ ((noinline)) helper_1(uint64_t* x) {
  uint64_t array[256];
  helper_2(&array[128]);
  *x = array[128];
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t array[256];
  helper_1(&array[128]);
  return array[128];
}

