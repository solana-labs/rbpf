typedef unsigned long int uint64_t;
typedef unsigned char uint8_t;

// 1811268606 = murmur32("log");
static void (*log)(const char*, uint64_t) = (void *) 1811268606;

extern uint64_t entrypoint(const uint8_t *input) {
  log("foo\n", 4);

  return 0;
}
