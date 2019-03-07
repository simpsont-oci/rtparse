#pragma once

#include <cstdint>

class fuzzy_bool {
public:

  fuzzy_bool();
  fuzzy_bool(bool val);

  fuzzy_bool& operator=(const fuzzy_bool& rhs);
  fuzzy_bool& operator=(bool rhs);

  operator bool() const;

  fuzzy_bool& merge(const fuzzy_bool& rhs);

private:

  enum fuzzy_bool_val : uint8_t {
    FBV_FALSE = 0x00,
    FBV_TRUE = 0x01,
    FBV_UNKNOWN = 0xFF
  };

  fuzzy_bool_val fbv;
};

