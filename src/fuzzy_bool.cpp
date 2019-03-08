#include "fuzzy_bool.hpp"

#include <iostream>

fuzzy_bool::fuzzy_bool() : fbv(FBV_UNKNOWN) {}
fuzzy_bool::fuzzy_bool(fuzzy_bool&& val) noexcept : fbv(val.fbv) {}
fuzzy_bool::fuzzy_bool(bool val) : fbv(val ? FBV_TRUE : FBV_FALSE) {}

fuzzy_bool& fuzzy_bool::operator=(fuzzy_bool&& rhs) noexcept {
  if (&rhs != this) {
    fbv = rhs.fbv;
  }
  return *this;
}

fuzzy_bool& fuzzy_bool::operator=(bool rhs) {
  fbv = rhs ? FBV_TRUE : FBV_FALSE;
  return *this;
}

fuzzy_bool::operator bool() const {
  if (fbv == FBV_UNKNOWN) {
    std::cout << "ERROR! fuzzy_bool value is still unknown!" << std::endl;
    return false;
  }
  return fbv == FBV_TRUE;
}

fuzzy_bool& fuzzy_bool::merge(const fuzzy_bool& rhs) {
  if (&rhs != this) {
    if (fbv == FBV_UNKNOWN) {
      fbv = rhs.fbv;
    } else if ((fbv == FBV_TRUE && rhs.fbv == FBV_FALSE) || (fbv == FBV_FALSE && rhs.fbv == FBV_TRUE)) {
      std::cout << "Error! fuzzy_bool unable to merge!" << std::endl;
    }
    // Otherwise it's safe to keep current value
  }
  return *this;
}

