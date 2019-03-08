#pragma once

#include <string>

bool is_mac_multicast(const std::string& mac);
bool is_ip_multicast(const std::string& ip);
bool is_id_builtin(const std::string& id);
bool is_guid_builtin(const std::string& guid);

std::string check_flag_string(uint16_t, std::string&& flags);
