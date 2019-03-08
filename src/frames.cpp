#include "frames.hpp"

std::vector<rtps_info_dst>::const_iterator find_previous_dst(const rtps_frame& frame, size_t sm_order_limit) {
  auto old = frame.info_dst_vec.cend();
  auto pos = frame.info_dst_vec.begin();
  while (pos != frame.info_dst_vec.end() && pos->sm_order < sm_order_limit) {
    old = pos;
    ++pos;
  }
  return old;
}

