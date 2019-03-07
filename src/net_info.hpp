#pragma once

#include <string>
#include <ostream>
#include <map>

struct net_info {
  net_info();
  net_info(const std::string& m, const std::string& i, const std::string& p);

  std::string mac;
  std::string ip;
  std::string port;
};

typedef std::map<std::string, net_info> net_info_map;

std::ostream& operator<<(std::ostream& os, const net_info& info);
std::ostream& operator<<(std::ostream& os, const net_info_map& nm);

bool merge_net_info(net_info& existing, const net_info& update);
bool create_or_merge_net_info(const net_info& info, net_info_map& nm);

