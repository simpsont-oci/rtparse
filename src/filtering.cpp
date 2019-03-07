#include "filtering.hpp"

void filter_spdp_announcements(const std::vector<std::pair<const rtps_frame*, const rtps_data*>>& in, size_t fnum, const std::string& wguid, const std::string& rguid, std::vector<std::pair<const rtps_frame*, const rtps_data*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    if (v.first->frame_no >= fnum) {
      if (!v.second->participant_guid.empty()) {
        if (v.second->participant_guid.substr(0, 24) == wguid.substr(0, 24) || v.second->participant_guid.substr(0, 24) == rguid.substr(0, 24)) {
          out.push_back(v);
        }
      }
    }
  });
}

void filter_sedp_announcements(const std::vector<std::pair<const rtps_frame*, const rtps_data*>>& in, size_t fnum, const std::string& wguid, const std::string& rguid, std::vector<std::pair<const rtps_frame*, const rtps_data*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    if (v.first->frame_no >= fnum) {
      if (!v.second->endpoint_guid.empty()) {
        if (v.second->endpoint_guid == wguid || v.second->endpoint_guid == rguid) {
          out.push_back(v);
        }
      }
    }
  });
}

