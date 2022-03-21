typedef unsigned long int uint64_t;
typedef unsigned char uint8_t;

volatile const uint64_t v1 = 41;
volatile const uint64_t v2 = 42;
volatile const uint64_t v3 = 43;

extern uint64_t entrypoint(const uint8_t *input) {
  return v2;
}
