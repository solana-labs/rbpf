typedef unsigned long int uint64_t;
typedef unsigned char uint8_t;

static void (*i_dont_exist)() = (void *) 42;

extern uint64_t entrypoint(const uint8_t *input) {
  i_dont_exist();

  return 0;
}
