#pragma once

#include "net_info.hpp"
#include "fuzzy_bool.hpp"
#include "info_pairs.hpp"

#include <string>
#include <vector>
#include <map>
#include <iostream>

struct endpoint_info {
  endpoint_info() : guid(), src_net(), domain_id(0xFF), first_evidence_frame(0), first_evidence_time(-1.0), reliable() {}
  endpoint_info(const endpoint_info& val) : guid(val.guid), src_net(val.src_net), dst_net_map(val.dst_net_map), domain_id(val.domain_id), first_evidence_frame(val.first_evidence_frame), first_evidence_time(val.first_evidence_time), reliable(val.reliable) {}

  std::string guid;
  net_info src_net;
  net_info_map dst_net_map;
  size_t domain_id;
  size_t first_evidence_frame;
  double first_evidence_time;
  fuzzy_bool reliable;
  std::vector<data_info_pair> spdp_announcements;
  std::vector<data_info_pair> sedp_announcements;
  std::vector<data_info_pair> datas;
  std::vector<gap_info_pair> gaps;
  std::vector<hb_info_pair> heartbeats;
  std::vector<an_info_pair> acknacks;
};

typedef std::map<std::string, endpoint_info> endpoint_map;

std::ostream& operator<<(std::ostream& os, const endpoint_info& info);

bool merge_endpoint_info(endpoint_info& existing, const endpoint_info& update);
bool create_or_merge_endpoint_info(const endpoint_info& info, endpoint_map& em);
void gather_participant_info(const rtps_frame_map& frames, endpoint_map& em);
void gather_endpoint_info(const rtps_frame_map& frames, endpoint_map& em);

