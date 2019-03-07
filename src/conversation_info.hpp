#pragma once

#include "endpoint_info.hpp"
#include "info_pairs.hpp"

#include <string>
#include <vector>

struct conversation_info {
  std::string writer_guid;
  std::string reader_guid;
  uint16_t domain_id;
  size_t first_evidence_frame;
  double first_evidence_time;
  std::vector<data_info_pair> datas;
  std::vector<gap_info_pair> gaps;
  std::vector<hb_info_pair> heartbeats;
  std::vector<an_info_pair> acknacks;
};

typedef std::map<std::string, std::map<std::string, conversation_info>> conversation_map;

void copy_endpoint_details_relevant_to_conversation(const endpoint_info& writer, const endpoint_info& reader, const endpoint_map& em, conversation_info& conv);
void gather_conversation_info(const rtps_frame_map& frames, const endpoint_map& em, conversation_map& cm);

