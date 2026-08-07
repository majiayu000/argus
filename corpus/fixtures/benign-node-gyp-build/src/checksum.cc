// Bundled source compiled locally. Nothing is downloaded or executed.
#include <cstddef>
#include <cstdint>

extern "C" uint32_t checksum(const uint8_t* data, size_t length) {
  uint32_t sum = 0;
  for (size_t index = 0; index < length; ++index) {
    sum = (sum << 1) ^ data[index];
  }
  return sum;
}
