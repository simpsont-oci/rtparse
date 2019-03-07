#include "utils.hpp"

#include <set>
#include <sstream>

bool is_mac_multicast(const std::string& mac) {
  return mac.substr(0, 3) == "01:";
}

bool is_ip_multicast(const std::string ip) {
  size_t pos = ip.find(".");
  if (pos != std::string::npos) {
    std::stringstream ss(ip.substr(0, pos));
    uint16_t temp;
    ss >> temp;
    return temp > 224;
  } else {
    return ip.substr(0, 2) == "FF" || ip.substr(0, 2) == "ff";
  }
}

bool is_id_builtin(const std::string& id) {
  static std::set<std::string> id_set;
  if (id_set.size() == 0) {
    id_set.insert("000002c2");
    id_set.insert("000002c7");
    id_set.insert("000003c2");
    id_set.insert("000003c7");
    id_set.insert("000004c2");
    id_set.insert("000004c7");
    id_set.insert("000100c2");
    id_set.insert("000100c7");
    id_set.insert("000200c2");
    id_set.insert("000200c7");
  }
  return id_set.find(id) != id_set.end();
}

bool is_guid_builtin(const std::string& guid) {
  return is_id_builtin(guid.substr(24, 8));
}

