#pragma once

#include "net_info.hpp"
#include "fuzzy_bool.hpp"
#include "info_pairs.hpp"

#include <iostream>
#include <map>
#include <string>
#include <vector>

struct endpoint_info {
  std::string guid;
  net_info src_net;
  net_info_map dst_net_map;
  size_t domain_id{0xFF};
  size_t first_evidence_frame{0};
  double first_evidence_time{-1.0};
  fuzzy_bool reliable;
  std::vector<data_info_pair> spdp_announcements;
  std::vector<data_info_pair> sedp_announcements;
  std::vector<data_info_pair> datas;
  std::vector<gap_info_pair> gaps;
  std::vector<hb_info_pair> heartbeats;
  std::vector<an_info_pair> acknacks;
};

using endpoint_map = std::map<std::string, endpoint_info>;

std::ostream& operator<<(std::ostream& os, const endpoint_info& info);

bool merge_endpoint_info(endpoint_info& existing, const endpoint_info& update);
bool create_or_merge_endpoint_info(const endpoint_info& info, endpoint_map& em);
void gather_participant_info(const rtps_frame_map& frames, endpoint_map& em);
void gather_endpoint_info(const rtps_frame_map& frames, endpoint_map& em);

