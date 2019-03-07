#pragma once

#include "common_types.hpp"
#include "frames.hpp"

#include <map>

typedef std::map<size_t, string_vec> tshark_frame_map;

bool process_frame_header(const string_vec& frame_header, rtps_frame& frame);
bool process_eth_header(const string_vec& eth_header, rtps_frame& frame);
bool process_ip_header(const string_vec& ip_header, rtps_frame& frame, ip_frag_map& ifm);
bool process_udp_header(const string_vec& udp_header, rtps_frame& frame);
bool process_rtps_header(const string_vec& rtps_header, rtps_frame& frame);
bool process_rtps_submessages(const std::vector<string_vec>& rtps_submessages, rtps_frame& frame);
bool process_rtps_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order);
bool process_rtps_info_dst_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order);
bool process_rtps_data_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order);
bool process_rtps_gap_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order);
bool process_rtps_heartbeat_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order);
bool process_rtps_acknack_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order);
void process_frame(const string_vec& tshark_frame_data, rtps_frame_map& frames, ip_frag_map& ifm);
void process_frame_data(const tshark_frame_map& fd, rtps_frame_map& frames, ip_frag_map& ifm);

