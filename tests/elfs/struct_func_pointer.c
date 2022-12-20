typedef unsigned long int uint64_t;
typedef unsigned char uint8_t;

struct PubkeyLutEntry {
  uint8_t (*fp)(uint8_t);
  uint64_t key;
};

uint8_t f1(uint8_t a) {
  return a + 1;
}

struct PubkeyLutEntry __attribute__((__section__(".data.rel.ro"))) E1 = { &f1, 0x0102030405060708 };

extern uint64_t entrypoint(const uint8_t *input) {
  return E1.key;
}
