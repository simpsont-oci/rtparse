#include "net_info.hpp"

#include <iostream>
#include <algorithm>

net_info::net_info() : mac(), ip(), port() {}
net_info::net_info(const std::string& m, const std::string& i, const std::string& p) : mac(m), ip(i), port(p) {}

std::ostream& operator<<(std::ostream& os, const net_info& info) {
  return os << "( " << info.mac << ", " << info.ip << ", " << info.port << " )" << std::flush;
}

std::ostream& operator<<(std::ostream& os, const std::map<std::string, net_info>& nm) {
  os << "[ " << std::flush;
  if (nm.size() > 0) {
    std::cout << nm.begin()->second << std::flush;
  }
  std::for_each(++(nm.begin()), nm.end(), [&](const auto& v) { os << ", " << v.second << std::flush; });
  return os << " ]" << std::flush;
}

bool merge_net_info(net_info& existing, const net_info& update) {
  if (existing.mac.empty())
    existing.mac = update.mac;
  if (existing.ip.empty())
    existing.ip = update.ip;
  if (existing.port.empty())
    existing.port = update.port;

  if ((existing.mac != update.mac && !update.mac.empty()) ||
      (existing.ip != update.ip && !update.ip.empty()) ||
      (existing.port != update.port && !update.port.empty())) {
    std::cout << "Contradictory network data found while merging entries for IP " << existing.ip << std::endl;
    std::cout << "Existing: " << existing << std::endl;
    std::cout << "Update:   " << update << std::endl;
    return false;
  }
  return true;
}

bool create_or_merge_net_info(const net_info& info, net_info_map& nm) {
  auto it = nm.find(info.ip);
  if (it != nm.end()) {
    return merge_net_info(it->second, info);
  } else {
    nm[info.ip] = info;
    return true;
  }
}

