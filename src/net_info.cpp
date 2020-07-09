#include "net_info.hpp"

#include <algorithm>
#include <iostream>
#include <utility>

net_info::net_info(std::string  m, std::string  i, std::string  p) : mac(std::move(m)), ip(std::move(i)), port(std::move(p)) {}

std::ostream& operator<<(std::ostream& os, const net_info& info) {
  return os << "( " << info.mac << ", " << info.ip << ", " << info.port << " )" << std::flush;
}

std::ostream& operator<<(std::ostream& os, const std::map<std::string, net_info>& nm) {
  os << "[ " << std::flush;
  if (!nm.empty()) {
    std::cout << nm.begin()->second << std::flush;
    std::for_each(++(nm.begin()), nm.end(), [&](const auto& v) { os << ", " << v.second << std::flush; });
  }
  return os << " ]" << std::flush;
}

bool merge_net_info(net_info& existing, const net_info& update) {
  if (existing.mac.empty()) {
    existing.mac = update.mac;
  }
  if (existing.ip.empty()) {
    existing.ip = update.ip;
  }
  if (existing.port.empty()) {
    existing.port = update.port;
  }

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
  } 

  nm[info.ip] = info;
  return true;
}

