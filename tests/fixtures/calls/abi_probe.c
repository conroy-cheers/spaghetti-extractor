struct triple {
  unsigned first;
  unsigned second;
  unsigned third;
};

struct triple fixture_call(unsigned value) {
  struct triple result = {value, value + 1u, value + 2u};
  return result;
}
