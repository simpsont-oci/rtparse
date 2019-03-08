#pragma once

#include "info_pairs.hpp"
#include "endpoint_info.hpp"

#include <algorithm>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

using data_info_pair_vec = std::vector<std::pair<const rtps_frame*, const rtps_data*>>;

void filter_spdp_announcements(const data_info_pair_vec& in, size_t fnum, const std::string& wguid, const std::string& rguid, data_info_pair_vec& out);
void filter_sedp_announcements(const data_info_pair_vec& in, size_t fnum, const std::string& wguid, const std::string& rguid, data_info_pair_vec& out);

template <typename T>
void filter_info_pair_vec_by_frame_and_reader_dst(const std::vector<std::pair<const rtps_frame*, const T*>>& in, size_t fnum, const std::string& guid, const net_info_map& nm, std::vector<std::pair<const rtps_frame*, const T*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    std::vector<rtps_info_dst>::const_iterator idit;
    if ((idit = find_previous_dst(*(v.first), v.second->sm_order)) != v.first->info_dst_vec.end()) {
      if (guid != (idit->guid_prefix + v.second->reader_id)) {
        return;
      }
    }
    if (v.first->frame_no >= fnum) {
      if (v.second->reader_id == "00000000" || v.second->reader_id == guid.substr(24, 8)) {
        auto it = nm.find(v.first->dst_ip);
        if (it != nm.end()) {
          out.push_back(v);
        }
      }
    }
  });
}

template <typename T>
void filter_info_pair_vec_by_frame_and_reader_dst_full(const std::vector<std::pair<const rtps_frame*, const T*>>& in, size_t fnum, const std::string& guid, const net_info_map& nm, std::vector<std::pair<const rtps_frame*, const T*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    std::vector<rtps_info_dst>::const_iterator idit;
    if ((idit = find_previous_dst(*(v.first), v.second->sm_order)) != v.first->info_dst_vec.end()) {
      if (guid != (idit->guid_prefix + v.second->reader_id)) {
        return;
      }
    }
    if (v.first->frame_no >= fnum) {
      if (v.second->reader_id == "00000000" || v.second->reader_id == guid.substr(24, 8)) {
        auto it = nm.find(v.first->dst_ip);
        if (it != nm.end()) {
          if ((it->second.mac != "" && it->second.mac != v.first->dst_mac) || (it->second.port != "" && it->second.port != v.first->dst_port)) {
            //std::cout << "filtering dst by mac and port makes a difference!" << std::endl;
          } else {
            out.push_back(v);
          }
        }
      }
    }
  });
}

template <typename T>
void filter_info_pair_vec_by_frame_and_writer_dst_full(const std::vector<std::pair<const rtps_frame*, const T*>>& in, size_t fnum, const std::string& guid, const net_info_map& nm, std::vector<std::pair<const rtps_frame*, const T*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    std::vector<rtps_info_dst>::const_iterator idit;
    if ((idit = find_previous_dst(*(v.first), v.second->sm_order)) != v.first->info_dst_vec.end()) {
      if (guid != (idit->guid_prefix + v.second->writer_id)) {
        return;
      }
    }
    if (v.first->frame_no >= fnum) {
      if (v.second->writer_id == "00000000" || v.second->writer_id == guid.substr(24, 8)) {
        auto it = nm.find(v.first->dst_ip);
        if (it != nm.end()) {
          if ((it->second.mac != "" && it->second.mac != v.first->dst_mac) || (it->second.port != "" && it->second.port != v.first->dst_port)) {
            //std::cout << "filtering dst by mac and port makes a difference!" << std::endl;
          } else {
            out.push_back(v);
          }
        }
      }
    }
  });
}

