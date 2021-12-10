typedef unsigned long int uint64_t;
typedef unsigned char uint8_t;

int val = 0;

extern uint64_t entrypoint(const uint8_t *input) {
  val = 43;
  return 0;
}
