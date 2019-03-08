#pragma once

#include <map>
#include <ostream>
#include <string>

struct net_info {
  net_info() = default;
  net_info(const net_info&) = default;
  net_info(net_info&&) = default;
  net_info(std::string m, std::string i, std::string p);

  ~net_info() = default;

  net_info& operator=(const net_info&) = default;
  net_info& operator=(net_info&&) = default;

  std::string mac;
  std::string ip;
  std::string port;
};

using net_info_map = std::map<std::string, net_info>;

std::ostream& operator<<(std::ostream& os, const net_info& info);
std::ostream& operator<<(std::ostream& os, const net_info_map& nm);

bool merge_net_info(net_info& existing, const net_info& update);
bool create_or_merge_net_info(const net_info& info, net_info_map& nm);

