#pragma once

#include "common_types.hpp"

#include <map>
#include <string>
#include <vector>

struct rtps_info_dst{
  size_t sm_order;
  uint16_t flags;
  std::string guid_prefix;
};

struct rtps_data {
  size_t sm_order;
  uint16_t flags;
  std::string writer_id;
  std::string reader_id;
  size_t writer_seq_num;
  bool unregistered;
  bool disposed;
  std::string participant_guid;
  string_vec metatraffic_unicast_locator_ips;
  string_vec metatraffic_unicast_locator_ports;
  string_vec metatraffic_multicast_locator_ips;
  string_vec metatraffic_multicast_locator_ports;
  uint32_t builtins;
  std::string endpoint_guid;
  string_vec unicast_locator_ips;
  string_vec unicast_locator_ports;
  string_vec multicast_locator_ips;
  string_vec multicast_locator_ports;
  string_vec registered_writers;
  bool endpoint_reliability;
};

struct rtps_heartbeat {
  size_t sm_order;
  uint16_t flags;
  std::string writer_id;
  std::string reader_id;
  size_t first_seq_num;
  size_t last_seq_num;
};

struct rtps_acknack {
  size_t sm_order;
  uint16_t flags;
  std::string writer_id;
  std::string reader_id;
  size_t bitmap_base;
  std::string bitmap;
};

struct rtps_gap {
  size_t sm_order;
  uint16_t flags;
  std::string writer_id;
  std::string reader_id;
  size_t gap_start;
  size_t bitmap_base;
  std::string bitmap;
};

struct rtps_frame {
  size_t frame_no;
  double frame_epoch_time;
  double frame_reference_time;
  std::string src_mac;
  std::string dst_mac;
  std::string src_ip;
  std::string dst_ip;
  std::string src_port;
  std::string dst_port;
  size_t udp_length;
  size_t domain_id;
  std::string guid_prefix;
  std::vector<rtps_info_dst> info_dst_vec;
  std::vector<rtps_data> data_vec;
  std::vector<rtps_gap> gap_vec;
  std::vector<rtps_heartbeat> heartbeat_vec;
  std::vector<rtps_acknack> acknack_vec;
};

using rtps_frame_map = std::map<size_t, rtps_frame>;
using ip_frag_map = std::map<std::string, std::pair<std::pair<size_t, double>, size_t>>;

std::vector<rtps_info_dst>::const_iterator find_previous_dst(const rtps_frame& frame, size_t sm_order_limit);


