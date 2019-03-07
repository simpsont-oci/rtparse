#include "boost/program_options/parsers.hpp"
#include "boost/program_options/variables_map.hpp"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <memory>

namespace po = boost::program_options;

typedef std::vector<std::string> string_vec;

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

typedef std::pair<const rtps_frame*, const rtps_data*> data_info_pair;
typedef std::pair<const rtps_frame*, const rtps_gap*> gap_info_pair;
typedef std::pair<const rtps_frame*, const rtps_heartbeat*> hb_info_pair;
typedef std::pair<const rtps_frame*, const rtps_acknack*> an_info_pair;

struct info_pair_printer_base {
  virtual ~info_pair_printer_base() {}
  virtual std::ostream& print(std::ostream& os) const = 0;
protected:
  info_pair_printer_base() {}
};

std::vector<rtps_info_dst>::const_iterator find_previous_dst(const rtps_frame& frame, size_t sm_order_limit);

struct data_info_pair_printer : public info_pair_printer_base {
  data_info_pair_printer(const data_info_pair& p) : pair(p) {}
  const data_info_pair& pair;
  std::ostream& print(std::ostream& os) const {
    const auto& frame = *(pair.first);
    const auto& data = *(pair.second);
    auto idit = find_previous_dst(frame, data.sm_order);
    std::string data_type = "Data";
    if (data.flags & 0x08) {
      data_type += std::string("[") + (data.unregistered ? (data.disposed ? "UD" : "U") : (data.disposed ? "D" : "_")) + "]";
    }
    if (!data.participant_guid.empty() || !data.endpoint_guid.empty()) {
      data_type += std::string("(") + (data.participant_guid.empty() ? (data.writer_id == "000003c2" ? "w" : "r") : "p") + ")";
    }
    std::string display_guid = (idit == frame.info_dst_vec.end() ? std::string("????????????????????????") : idit->guid_prefix) + data.reader_id;
    std::string flagstr = std::string(data.flags & 0x08 ? "K" : "-") + (data.flags & 0x04 ? "D" : "-") + (data.flags & 0x02 ? "Q" : "-") + (data.flags & 0x01 ? "E" : "-");
    os << " - " + data_type << " in frame" << std::string(10 - data_type.size(), ' ')
      << std::setw(6) << frame.frame_no << " at time " << std::setw(7) << std::fixed << std::setprecision(3) << frame.frame_reference_time
      << " sent to " << display_guid << " @ " << frame.dst_ip << ":" << frame.dst_port
      << " :: flags = " << flagstr << ", length = " << frame.udp_length << ", seq_num = " << data.writer_seq_num << std::flush;
    if (!data.participant_guid.empty()) {
      os << ", participant_guid = " << data.participant_guid << std::flush;
    }
    if (!data.endpoint_guid.empty()) {
      os << ", endpoint_guid = " << data.endpoint_guid << std::flush;
    }
    return os;
  }
};

struct gap_info_pair_printer : public info_pair_printer_base {
  gap_info_pair_printer(const gap_info_pair& p) : pair(p) {}
  const gap_info_pair& pair;
  std::ostream& print(std::ostream& os) const {
    const auto& frame = *(pair.first);
    const auto& gap = *(pair.second);
    auto idit = find_previous_dst(frame, gap.sm_order);
    std::string display_guid = (idit == frame.info_dst_vec.end() ? std::string("????????????????????????") : idit->guid_prefix) + gap.reader_id;
    std::string flagstr = std::string("---") + (gap.flags & 0x01 ? "E" : "-");
    return os << " - Gap in frame       " << std::setw(6) << frame.frame_no << " at time " << std::setw(7) << std::fixed << std::setprecision(3) << frame.frame_reference_time
      << " sent to " << display_guid << " @ " << frame.dst_ip << ":" << frame.dst_port
      << " :: flags = " << flagstr << ", start = " << gap.gap_start << ", base = " << gap.bitmap_base << ", bitmap = " << gap.bitmap  << std::flush;
  }
};

struct hb_info_pair_printer : public info_pair_printer_base {
  hb_info_pair_printer(const hb_info_pair& p) : pair(p) {}
  const hb_info_pair& pair;
  std::ostream& print(std::ostream& os) const {
    const auto& frame = *(pair.first);
    const auto& heartbeat = *(pair.second);
    auto idit = find_previous_dst(frame, heartbeat.sm_order);
    std::string display_guid = (idit == frame.info_dst_vec.end() ? std::string("????????????????????????") : idit->guid_prefix) + heartbeat.reader_id;
    std::string flagstr = std::string("-") + (heartbeat.flags & 0x04 ? "L" : "-") + (heartbeat.flags & 0x02 ? "F" : "-") + (heartbeat.flags & 0x01 ? "E" : "-");
    return os << " - Heartbeat in frame " << std::setw(6) << frame.frame_no << " at time " << std::setw(7) << std::fixed << std::setprecision(3) << frame.frame_reference_time
      << " sent to " << display_guid << " @ " << frame.dst_ip << ":" << frame.dst_port
      << " :: flags = " << flagstr << ", first = " << heartbeat.first_seq_num << ", last = " << heartbeat.last_seq_num << std::flush;
  }
};

struct an_info_pair_printer : public info_pair_printer_base {
  an_info_pair_printer(const an_info_pair& p) : pair(p) {}
  const an_info_pair& pair;
  std::ostream& print(std::ostream& os) const {
    const auto& frame = *(pair.first);
    const auto& acknack = *(pair.second);
    auto idit = find_previous_dst(frame, acknack.sm_order);
    std::string display_guid = (idit == frame.info_dst_vec.end() ? std::string("????????????????????????") : idit->guid_prefix) + acknack.writer_id;
    std::string flagstr = std::string("--") + (acknack.flags & 0x02 ? "F" : "-") + (acknack.flags & 0x01 ? "E" : "-");
    return os << " - Acknack in frame   " << std::setw(6) << frame.frame_no << " at time " << std::setw(7) << std::fixed << std::setprecision(3) << frame.frame_reference_time
      << " sent to " << display_guid << " @ " << frame.dst_ip << ":" << frame.dst_port
      << " :: flags = " << flagstr << ", base = " << acknack.bitmap_base << ", bitmap = " << acknack.bitmap  << std::flush;
  }
};

class FuzzyBool {
public:
  FuzzyBool() : fbv(FBV_UNKNOWN) {}
  FuzzyBool(bool val) : fbv(val ? FBV_TRUE : FBV_FALSE) {}

  FuzzyBool& operator=(const FuzzyBool& rhs) {
    if (&rhs != this) {
      fbv = rhs.fbv;
    }
    return *this;
  }

  FuzzyBool& merge(const FuzzyBool& rhs) {
    if (&rhs != this) {
      if (fbv == FBV_UNKNOWN) {
        fbv = rhs.fbv;
      } else if ((fbv == FBV_TRUE && rhs.fbv == FBV_FALSE) || (fbv == FBV_FALSE && rhs.fbv == FBV_TRUE)) {
        std::cout << "Error! FuzzyBool unable to merge!" << std::endl;
      }
      // Otherwise it's safe to keep current value
    }
    return *this;
  }

  FuzzyBool& operator=(bool rhs) {
    fbv = rhs ? FBV_TRUE : FBV_FALSE;
    return *this;
  }

  operator bool() const {
    if (fbv == FBV_UNKNOWN) {
      std::cout << "ERROR! FuzzyBool value is still unknown!" << std::endl;
      return false;
    }
    return fbv == FBV_TRUE ? true : false;
  }

private:

  enum FuzzyBoolVal : uint8_t {
    FBV_FALSE = 0x00,
    FBV_TRUE = 0x01,
    FBV_UNKNOWN = 0xFF
  };

  FuzzyBoolVal fbv;
};

struct net_info {
  net_info() : mac(), ip(), port() {}
  net_info(const std::string& m, const std::string& i, const std::string& p) : mac(m), ip(i), port(p) {}

  std::string mac;
  std::string ip;
  std::string port;
};

std::ostream& operator<<(std::ostream& os, const net_info& info);

std::ostream& operator<<(std::ostream& os, const net_info& info) {
  return os << "( " << info.mac << ", " << info.ip << ", " << info.port << " )" << std::flush;
}

std::ostream& operator<<(std::ostream& os, const std::map<std::string, net_info>& nm);

std::ostream& operator<<(std::ostream& os, const std::map<std::string, net_info>& nm) {
  os << "[ " << std::flush;
  if (nm.size() > 0) {
    std::cout << nm.begin()->second << std::flush;
  }
  std::for_each(++(nm.begin()), nm.end(), [&](const auto& v) { os << ", " << v.second << std::flush; });
  return os << " ]" << std::flush;
}

struct endpoint_info {
  endpoint_info() : guid(), src_net(), domain_id(0xFF), first_evidence_frame(0), first_evidence_time(-1.0), reliable() {}
  endpoint_info(const endpoint_info& val) : guid(val.guid), src_net(val.src_net), dst_net_map(val.dst_net_map), domain_id(val.domain_id), first_evidence_frame(val.first_evidence_frame), first_evidence_time(val.first_evidence_time), reliable(val.reliable) {}

  std::string guid;
  net_info src_net;
  std::map<std::string, net_info> dst_net_map;
  size_t domain_id;
  size_t first_evidence_frame;
  double first_evidence_time;
  FuzzyBool reliable;
  std::vector<data_info_pair> spdp_announcements;
  std::vector<data_info_pair> sedp_announcements;
  std::vector<data_info_pair> datas;
  std::vector<gap_info_pair> gaps;
  std::vector<hb_info_pair> heartbeats;
  std::vector<an_info_pair> acknacks;
};

typedef std::map<std::string, endpoint_info> endpoint_map;

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

std::ostream& operator<<(std::ostream& os, const endpoint_info& info);

std::ostream& operator<<(std::ostream& os, const endpoint_info& info) {
  return os << "( " << info.guid << ", " << info.src_net << ", " << info.dst_net_map << ", " << info.domain_id << ", " << info.first_evidence_frame << ", " << std::fixed << std::setprecision(3) << info.first_evidence_time << " )" << std::flush;
}

typedef std::map<std::string, std::pair<std::pair<size_t, double>, size_t>> ip_frag_map;

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
void process_frame(const string_vec& frame_data, std::map<size_t, rtps_frame>& frames, ip_frag_map& ifm);
void process_frame_data(const std::map<size_t, string_vec>& frame_data, std::map<size_t, rtps_frame>& frames, ip_frag_map& ifm);
bool is_mac_multicast(const std::string& mac);
bool is_ip_multicast(const std::string ip);
bool merge_net_info(net_info& existing, const net_info& update);
bool create_or_merge_net_info(const net_info& info, std::map<std::string, net_info>& nm);
bool merge_endpoint_info(endpoint_info& existing, const endpoint_info& update);
bool create_or_merge_endpoint_info(const endpoint_info& info, endpoint_map& em);
void gather_participant_info(const std::map<size_t, rtps_frame>& frames, endpoint_map& em);
void gather_endpoint_info(const std::map<size_t, rtps_frame>& frames, endpoint_map& em);
void gather_conversation_info(const std::map<size_t, rtps_frame>& frames, const endpoint_map& em, conversation_map& cm);

bool process_frame_header(const string_vec& frame_header, rtps_frame& frame) {
  bool result = false;
  size_t frame_no = 0;
  double frame_epoch_time = -1.0;
  double frame_reference_time = -1.0;

  for (auto it = frame_header.begin(); it != frame_header.end(); ++it) {
    size_t tpos, npos, rpos;
    if ((tpos = it->find("Epoch Time: ")) != std::string::npos) {
      std::stringstream ss(it->substr(tpos + 12));
      //std::cout << ss.str() << std::endl;
      ss >> frame_epoch_time;
    } else if ((npos = it->find("Frame Number: ")) != std::string::npos) {
      std::stringstream ss(it->substr(npos + 14));
      //std::cout << ss.str() << std::endl;
      ss >> frame_no;
    } else if ((rpos = it->find("[Time since reference or first frame: ")) != std::string::npos) {
      std::stringstream ss(it->substr(rpos + 38)); // This will have some cruft on the end, but stringstream's >> should ignore it
      //std::cout << ss.str() << std::endl;
      ss >> frame_reference_time;
    }
  }

  if (frame_no != 0 && frame_epoch_time >= 0.0) {
    frame.frame_no = frame_no;
    frame.frame_epoch_time = frame_epoch_time;
    frame.frame_reference_time = frame_reference_time;
    result = true;
  }
  return result;
}

bool process_eth_header(const string_vec& eth_header, rtps_frame& frame) {
  bool result = false;
  std::string src_mac;
  std::string dst_mac;

  bool linux_cooked_capture = (eth_header.front() == "Linux cooked capture");

  for (auto it = eth_header.begin(); it != eth_header.end(); ++it) {
    size_t spos, dpos;
    if ((spos = it->find("Source: ")) != std::string::npos) {
      std::string full = it->substr(spos + 8);
      if ((spos = full.find(" (")) != std::string::npos) {
        src_mac = full.substr(spos + 2, 17);
      } else {
        src_mac = full;
      }
      //std::cout << src_mac << std::endl;
    } else if ((dpos = it->find("Destination: ")) != std::string::npos) {
      std::string full = it->substr(dpos + 13);
      if ((dpos = full.find(" (")) != std::string::npos) {
        dst_mac = full.substr(dpos + 2, 17);
      } else {
        dst_mac = full;
      }
      //std::cout << dst_mac << std::endl;
    }
  }

  if (src_mac == "00:00:00:00:00:00") {
    src_mac = "";
  }

  if (linux_cooked_capture) {
    dst_mac = src_mac;
  }

  if (linux_cooked_capture || (!src_mac.empty() && !dst_mac.empty())) {
    frame.src_mac = src_mac;
    frame.dst_mac = dst_mac;
    result = true;
  }
  return result;
}

bool process_ip_header(const string_vec& ip_header, rtps_frame& frame, ip_frag_map& ifm) {
  bool result = false;
  bool ip_fragmentation = false;
  std::string src_ip;
  std::string dst_ip;
  std::string id;
  size_t frag_off = 0;

  for (auto it = ip_header.begin(); it != ip_header.end(); ++it) {
    size_t spos, dpos, fpos, ipos;
    if ((spos = it->find("Source: ")) != std::string::npos) {
      src_ip = it->substr(spos + 8);
      //std::cout << src_ip << std::endl;
    } else if ((dpos = it->find("Destination: ")) != std::string::npos) {
      dst_ip = it->substr(dpos + 13);
      //std::cout << dst_ip << std::endl;
    } else if (it->find("More fragments: Set") != std::string::npos) {
      ip_fragmentation = true;
    } else if ((fpos = it->find("Fragment offset: ")) != std::string::npos) {
      std::string full = it->substr(fpos + 17);
      std::stringstream ss(full);
      ss >> frag_off;
    } else if ((ipos = it->find("Identification: ")) != std::string::npos) {
      id = it->substr(ipos + 16);
    }
  }

  std::string full_id = id + "," + src_ip + "," + dst_ip;

  if (ip_fragmentation) {
    auto iter = ifm.find(id);
    if (iter == ifm.end()) {
      ifm[full_id].first = std::make_pair(frame.frame_no, frame.frame_reference_time);
      ifm[full_id].second = 0;
    }
  } else if (!src_ip.empty() && !dst_ip.empty()) {
    if (frag_off != 0) {
      auto iter = ifm.find(full_id);
      if (iter != ifm.end()) {
        if (iter->second.second != 0) {
          std::cout << "ip fragmentation id / src / dst collision!" << std::endl;
        }
        iter->second.second = frame.frame_no;
      }
    }
    frame.src_ip = src_ip;
    frame.dst_ip = dst_ip;
    result = true;
  }
  return result;
}

bool process_udp_header(const string_vec& udp_header, rtps_frame& frame) {
  bool result = false;
  std::string src_port;
  std::string dst_port;
  size_t udp_length = 0;

  for (auto it = udp_header.begin(); it != udp_header.end(); ++it) {
    size_t spos, dpos, lpos;
    if ((spos = it->find("Source Port: ")) != std::string::npos) {
      src_port = it->substr(spos + 13);
      //std::cout << src_port << std::endl;
    } else if ((dpos = it->find("Destination Port: ")) != std::string::npos) {
      dst_port = it->substr(dpos + 18);
      //std::cout << dst_port << std::endl;
    } else if ((dpos = it->find("Length: ")) != std::string::npos) {
      std::stringstream ss(it->substr(dpos + 8));
      ss >> udp_length;
      //std::cout << udp_length << std::endl;
    }
  }

  if (!src_port.empty() && !dst_port.empty()) {
    frame.src_port = src_port;
    frame.dst_port = dst_port;
    frame.udp_length = udp_length;
    result = true;
  }
  return result;
}

bool process_rtps_header(const string_vec& rtps_header, rtps_frame& frame) {
  bool result = false;
  uint16_t domain_id = 0xFFFF;
  std::string guid_prefix;

  for (auto it = rtps_header.begin(); it != rtps_header.end(); ++it) {
    size_t gpos, dpos;
    if ((gpos = it->find("guidPrefix: ")) != std::string::npos) {
      guid_prefix = it->substr(gpos + 12);
      //std::cout << guid_prefix << std::endl;
    } else if ((dpos = it->find("domain_id: ")) != std::string::npos) {
      std::stringstream ss(it->substr(dpos + 11));
      ss >> domain_id;
      //std::cout << domain_id << std::endl;
    }
  }

  if (domain_id != 0xFFFF && !guid_prefix.empty()) {
    frame.domain_id = domain_id;
    frame.guid_prefix = guid_prefix;
    result = true;
  }
  return result;
}

bool process_rtps_info_dst_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order) {
  bool result = false;
  uint16_t flags = 0xFFFF;
  std::string guid_prefix;

  //std::cout << "info_dst submessage:" << std::endl;
  if (rtps_submessage.size() > 1) {
    size_t fpos;
    if ((fpos = rtps_submessage[1].find("Flags: ")) != std::string::npos) {
      std::stringstream ss(rtps_submessage[1].substr(fpos + 7));
      ss >> std::hex >> flags;
      //std::cout << " - flags = " << flags << std::endl;
    }
  }

  for (auto it = rtps_submessage.begin(); it != rtps_submessage.end(); ++it) {
    size_t gpos;
    if ((gpos = it->find("guidPrefix: ")) != std::string::npos) {
      guid_prefix = it->substr(gpos + 12);
      //std::cout << " - guid_prefix = " << guid_prefix << std::endl;
    }
  }

  if (flags != 0xFFFF && !guid_prefix.empty()) {
    rtps_info_dst info_dst;
    info_dst.flags = flags;
    info_dst.guid_prefix = guid_prefix;
    info_dst.sm_order = sm_order;
    frame.info_dst_vec.push_back(info_dst);
    result = true;
  }
  return result;
}

bool process_rtps_data_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order) {
  bool result = false;
  uint16_t flags = 0xFFFF;
  std::string reader_id;
  std::string writer_id;
  size_t writer_seq_num;
  std::string participant_guid;
  string_vec metatraffic_unicast_locator_ips;
  string_vec metatraffic_unicast_locator_ports;
  string_vec metatraffic_multicast_locator_ips;
  string_vec metatraffic_multicast_locator_ports;
  std::string endpoint_guid;
  string_vec unicast_locator_ips;
  string_vec unicast_locator_ports;
  string_vec multicast_locator_ips;
  string_vec multicast_locator_ports;
  string_vec registered_writers;
  bool endpoint_reliability = false;
  bool unregistered = false;
  bool disposed = false;

  //std::cout << "data submessage:" << std::endl;
  if (rtps_submessage.size() > 1) {
    size_t fpos;
    if ((fpos = rtps_submessage[1].find("Flags: ")) != std::string::npos) {
      std::stringstream ss(rtps_submessage[1].substr(fpos + 7));
      ss >> std::hex >> flags;
      //std::cout << " - flags = " << flags << std::endl;
    }
  }

  for (auto it = rtps_submessage.begin(); it != rtps_submessage.end(); ++it) {
    size_t rpos, wpos, spos, pgpos, egpos, mulpos, ulpos, rwpos;
    if ((rpos = it->find("readerEntityId: 0x")) != std::string::npos) {
      reader_id = it->substr(rpos + 18, 8);
      //std::cout << " - reader_id = " << reader_id << std::endl;
    } else if ((rpos = it->find("readerEntityId: ")) != std::string::npos) {
      std::string full = it->substr(rpos + 16);
      if ((rpos = full.find("(0x")) != std::string::npos) {
        reader_id = full.substr(rpos + 3, 8);
        //std::cout << " - reader_id = " << reader_id << std::endl;
      }
    } else if ((wpos = it->find("writerEntityId: 0x")) != std::string::npos) {
      writer_id = it->substr(wpos + 18, 8);
      //std::cout << " - writer_id = " << writer_id << std::endl;
    } else if ((wpos = it->find("writerEntityId: ")) != std::string::npos) {
      std::string full = it->substr(wpos + 16);
      if ((wpos = full.find("(0x")) != std::string::npos) {
        writer_id = full.substr(wpos + 3, 8);
        //std::cout << " - writer_id = " << writer_id << std::endl;
      }
    } else if (it->find(" = Unregistered: Set") != std::string::npos) {
      unregistered = true;
      //std::cout << " - unregistered = " << unregistered << std::endl;
    } else if (it->find(" = Disposed: Set") != std::string::npos) {
      disposed = true;
      //std::cout << " - disposed = " << disposed << std::endl;
    } else if ((spos = it->find("writerSeqNumber: ")) != std::string::npos) {
      std::string full = it->substr(spos + 17);
      std::stringstream ss(full);
      ss >> writer_seq_num;
      //std::cout << " - writer_seq_num = " << writer_seq_num << std::endl;
    } else if ((pgpos = it->find("Participant GUID: ")) != std::string::npos) {
      std::string full = it->substr(pgpos + 18);
      std::stringstream ss(full);
      for (int i = 0; i < 4; ++i) {
        std::string quarter;
        ss >> quarter;
        participant_guid += quarter;
      }
      //std::cout << " - participant_guid = " << participant_guid << std::endl;
    } else if ((egpos = it->find("Endpoint GUID: ")) != std::string::npos) {
      std::string full = it->substr(egpos + 15);
      std::stringstream ss(full);
      for (int i = 0; i < 4; ++i) {
        std::string quarter;
        ss >> quarter;
        endpoint_guid += quarter;
      }
      //std::cout << " - endpoint_guid = " << endpoint_guid << std::endl;
    } else if ((mulpos = it->find("  PID_METATRAFFIC_UNICAST_LOCATOR (")) != std::string::npos) {
      std::string full = it->substr(mulpos + 35);
      std::stringstream ss(full);
      std::string kind_comma, ip_port_paren;
      ss >> kind_comma >> ip_port_paren;
      auto cpos = ip_port_paren.find(":");
      metatraffic_unicast_locator_ips.emplace_back(ip_port_paren.substr(0, cpos));
      metatraffic_unicast_locator_ports.emplace_back(ip_port_paren.substr(cpos + 1, ip_port_paren.find(")") - (cpos + 1)));
      //std::cout << " - metatraffic_unicast_locator_ip = " << metatraffic_unicast_locator_ips.back() << std::endl;
      //std::cout << " - metatraffic_unicast_locator_port = " << metatraffic_unicast_locator_ports.back() << std::endl;
    } else if ((mulpos = it->find("  PID_METATRAFFIC_MULTICAST_LOCATOR (")) != std::string::npos) {
      std::string full = it->substr(mulpos + 37);
      std::stringstream ss(full);
      std::string kind_comma, ip_port_paren;
      ss >> kind_comma >> ip_port_paren;
      auto cpos = ip_port_paren.find(":");
      metatraffic_multicast_locator_ips.emplace_back(ip_port_paren.substr(0, cpos));
      metatraffic_multicast_locator_ports.emplace_back(ip_port_paren.substr(cpos + 1, ip_port_paren.find(")") - (cpos + 1)));
      //std::cout << " - metatraffic_multicast_locator_ip = " << metatraffic_multicast_locator_ips.back() << std::endl;
      //std::cout << " - metatraffic_multicast_locator_port = " << metatraffic_multicast_locator_ports.back() << std::endl;
    } else if ((mulpos = it->find("  PID_UNICAST_LOCATOR (")) != std::string::npos) {
      std::string full = it->substr(mulpos + 23);
      std::stringstream ss(full);
      std::string kind_comma, ip_port_paren;
      ss >> kind_comma >> ip_port_paren;
      auto cpos = ip_port_paren.find(":");
      unicast_locator_ips.emplace_back(ip_port_paren.substr(0, cpos));
      unicast_locator_ports.emplace_back(ip_port_paren.substr(cpos + 1, ip_port_paren.find(")") - (cpos + 1)));
      //std::cout << " - unicast_locator_ip = " << unicast_locator_ips.back() << std::endl;
      //std::cout << " - unicast_locator_port = " << unicast_locator_ports.back() << std::endl;
    } else if ((mulpos = it->find("  PID_MULTICAST_LOCATOR (")) != std::string::npos) {
      std::string full = it->substr(mulpos + 25);
      std::stringstream ss(full);
      std::string kind_comma, ip_port_paren;
      ss >> kind_comma >> ip_port_paren;
      auto cpos = ip_port_paren.find(":");
      multicast_locator_ips.emplace_back(ip_port_paren.substr(0, cpos));
      multicast_locator_ports.emplace_back(ip_port_paren.substr(cpos + 1, ip_port_paren.find(")") - (cpos + 1)));
      //std::cout << " - multicast_locator_ip = " << multicast_locator_ips.back() << std::endl;
      //std::cout << " - multicast_locator_port = " << multicast_locator_ports.back() << std::endl;
    } else if ((rwpos = it->find("  Unknown (0xb002)")) != std::string::npos) {
      auto it2 = it; ++it2; ++it2; ++it2;
      if ((rwpos = it2->find("parameterData: ")) != std::string::npos) {
        std::string guid = it2->substr(rwpos + 15);
        registered_writers.push_back(guid);
        //std::cout << " - registered writer " << guid << std::endl;
      }
    } else if ((rpos = it->find("  PID_RELIABILITY")) != std::string::npos) {
      auto it2 = it; ++it2; ++it2; ++it2;
      if ((rpos = it2->find("Kind: ")) != std::string::npos) {
        std::string kind = it2->substr(rpos + 6);
        endpoint_reliability = (kind == "RELIABLE_RELIABILITY_QOS (0x00000002)");
        //std::cout << " - endpoint_reliability " << endpoint_reliability << std::endl;
      }
    }
  }

  if (flags != 0xFFFF && !reader_id.empty() && !writer_id.empty()) {
    rtps_data data;
    data.flags = flags;
    data.reader_id = reader_id;
    data.writer_id = writer_id;
    data.writer_seq_num = writer_seq_num;
    data.unregistered = unregistered;
    data.disposed = disposed;
    if (participant_guid.length() == 32) {
      data.participant_guid = participant_guid;
      data.metatraffic_unicast_locator_ips = metatraffic_unicast_locator_ips;
      data.metatraffic_unicast_locator_ports = metatraffic_unicast_locator_ports;
      data.metatraffic_multicast_locator_ips = metatraffic_multicast_locator_ips;
      data.metatraffic_multicast_locator_ports = metatraffic_multicast_locator_ports;
    }
    if (endpoint_guid.length() == 32) {
      data.endpoint_guid = endpoint_guid;
      data.unicast_locator_ips = unicast_locator_ips;
      data.unicast_locator_ports = unicast_locator_ports;
      data.multicast_locator_ips = multicast_locator_ips;
      data.multicast_locator_ports = multicast_locator_ports;
      data.registered_writers = registered_writers;
      data.endpoint_reliability = endpoint_reliability;
    }
    data.sm_order = sm_order;
    frame.data_vec.push_back(data);
    result = true;
  }
  return result;
}

bool process_rtps_gap_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order) {
  bool result = false;
  uint16_t flags = 0xFFFF;
  std::string reader_id;
  std::string writer_id;
  size_t gap_start = 0;
  size_t bitmap_base = 0;
  std::string bitmap;

  //std::cout << "gap submessage:" << std::endl;
  if (rtps_submessage.size() > 1) {
    size_t fpos;
    if ((fpos = rtps_submessage[1].find("Flags: ")) != std::string::npos) {
      std::stringstream ss(rtps_submessage[1].substr(fpos + 7));
      ss >> std::hex >> flags;
      //std::cout << " - flags = " << flags << std::endl;
    }
  }

  for (auto it = rtps_submessage.begin(); it != rtps_submessage.end(); ++it) {
    size_t rpos, wpos, bpos;
    if ((rpos = it->find("readerEntityId: 0x")) != std::string::npos) {
      reader_id = it->substr(rpos + 18, 8);
      //std::cout << " - reader_id = " << reader_id << std::endl;
    } else if ((rpos = it->find("readerEntityId: ")) != std::string::npos) {
      std::string full = it->substr(rpos + 16);
      if ((rpos = full.find("(0x")) != std::string::npos) {
        reader_id = full.substr(rpos + 3, 8);
        //std::cout << " - reader_id = " << reader_id << std::endl;
      }
    } else if ((wpos = it->find("writerEntityId: 0x")) != std::string::npos) {
      writer_id = it->substr(wpos + 18, 8);
      //std::cout << " - writer_id = " << writer_id << std::endl;
    } else if ((wpos = it->find("writerEntityId: ")) != std::string::npos) {
      std::string full = it->substr(wpos + 16);
      if ((wpos = full.find("(0x")) != std::string::npos) {
        writer_id = full.substr(wpos + 3, 8);
        //std::cout << " - writer_id = " << writer_id << std::endl;
      }
    } else if ((bpos = it->find("gapStart: ")) != std::string::npos) {
      std::string full = it->substr(bpos + 10);
      std::stringstream ss(full);
      ss >> gap_start;
    } else if ((bpos = it->find("bitmapBase: ")) != std::string::npos) {
      std::string full = it->substr(bpos + 12);
      std::stringstream ss(full);
      ss >> bitmap_base;
    } else if ((bpos = it->find("bitmap: ")) != std::string::npos) {
      bitmap = it->substr(bpos + 8);
    }
  }

  if (flags != 0xFFFF && !reader_id.empty() && !writer_id.empty()) {
    rtps_gap gap;
    gap.flags = flags;
    gap.reader_id = reader_id;
    gap.writer_id = writer_id;
    gap.gap_start = gap_start;
    gap.bitmap_base = bitmap_base;
    gap.bitmap = bitmap;
    gap.sm_order = sm_order;
    frame.gap_vec.push_back(gap);
    result = true;
  }
  return result;
}

bool process_rtps_heartbeat_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order) {
  bool result = false;
  uint16_t flags = 0xFFFF;
  std::string reader_id;
  std::string writer_id;
  size_t first_sequence_number;
  size_t last_sequence_number;

  //std::cout << "heartbeat submessage:" << std::endl;
  if (rtps_submessage.size() > 1) {
    size_t fpos;
    if ((fpos = rtps_submessage[1].find("Flags: ")) != std::string::npos) {
      std::stringstream ss(rtps_submessage[1].substr(fpos + 7));
      ss >> std::hex >> flags;
      //std::cout << " - flags = " << flags << std::endl;
    }
  }

  for (auto it = rtps_submessage.begin(); it != rtps_submessage.end(); ++it) {
    size_t rpos, wpos, spos;
    if ((rpos = it->find("readerEntityId: 0x")) != std::string::npos) {
      reader_id = it->substr(rpos + 18, 8);
      //std::cout << " - reader_id = " << reader_id << std::endl;
    } else if ((rpos = it->find("readerEntityId: ")) != std::string::npos) {
      std::string full = it->substr(rpos + 16);
      if ((rpos = full.find("(0x")) != std::string::npos) {
        reader_id = full.substr(rpos + 3, 8);
        //std::cout << " - reader_id = " << reader_id << std::endl;
      }
    } else if ((wpos = it->find("writerEntityId: 0x")) != std::string::npos) {
      writer_id = it->substr(wpos + 18, 8);
      //std::cout << " - writer_id = " << writer_id << std::endl;
    } else if ((wpos = it->find("writerEntityId: ")) != std::string::npos) {
      std::string full = it->substr(wpos + 16);
      if ((wpos = full.find("(0x")) != std::string::npos) {
        writer_id = full.substr(wpos + 3, 8);
        //std::cout << " - writer_id = " << writer_id << std::endl;
      }
    } else if ((spos = it->find("firstAvailableSeqNumber: ")) != std::string::npos) {
      std::string full = it->substr(spos + 25);
      std::stringstream ss(full);
      ss >> first_sequence_number;
      //std::cout << " - first_sequence_number = " << first_sequence_number << std::endl;
    } else if ((spos = it->find("lastSeqNumber: ")) != std::string::npos) {
      std::string full = it->substr(spos + 15);
      std::stringstream ss(full);
      ss >> last_sequence_number;
      //std::cout << " - last_sequence_number = " << last_sequence_number << std::endl;
    }
  }

  if (flags != 0xFFFF && !reader_id.empty() && !writer_id.empty()) {
    rtps_heartbeat heartbeat;
    heartbeat.flags = flags;
    heartbeat.reader_id = reader_id;
    heartbeat.writer_id = writer_id;
    heartbeat.first_seq_num = first_sequence_number;
    heartbeat.last_seq_num = last_sequence_number;
    heartbeat.sm_order = sm_order;
    frame.heartbeat_vec.push_back(heartbeat);
    result = true;
  }
  return result;
}

bool process_rtps_acknack_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order) {
  bool result = false;
  uint16_t flags = 0xFFFF;
  std::string reader_id;
  std::string writer_id;
  size_t bitmap_base = 0;
  std::string bitmap;

  //std::cout << "acknack submessage:" << std::endl;
  if (rtps_submessage.size() > 1) {
    size_t fpos;
    if ((fpos = rtps_submessage[1].find("Flags: ")) != std::string::npos) {
      std::stringstream ss(rtps_submessage[1].substr(fpos + 7));
      ss >> std::hex >> flags;
      //std::cout << " - flags = " << flags << std::endl;
    }
  }

  for (auto it = rtps_submessage.begin(); it != rtps_submessage.end(); ++it) {
    size_t rpos, wpos, bpos;
    if ((rpos = it->find("readerEntityId: 0x")) != std::string::npos) {
      reader_id = it->substr(rpos + 18, 8);
      //std::cout << " - reader_id = " << reader_id << std::endl;
    } else if ((rpos = it->find("readerEntityId: ")) != std::string::npos) {
      std::string full = it->substr(rpos + 16);
      if ((rpos = full.find("(0x")) != std::string::npos) {
        reader_id = full.substr(rpos + 3, 8);
        //std::cout << " - reader_id = " << reader_id << std::endl;
      }
    } else if ((wpos = it->find("writerEntityId: 0x")) != std::string::npos) {
      writer_id = it->substr(wpos + 18, 8);
      //std::cout << " - writer_id = " << writer_id << std::endl;
    } else if ((wpos = it->find("writerEntityId: ")) != std::string::npos) {
      std::string full = it->substr(wpos + 16);
      if ((wpos = full.find("(0x")) != std::string::npos) {
        writer_id = full.substr(wpos + 3, 8);
        //std::cout << " - writer_id = " << writer_id << std::endl;
      }
    } else if ((bpos = it->find("bitmapBase: ")) != std::string::npos) {
      std::string full = it->substr(bpos + 12);
      std::stringstream ss(full);
      ss >> bitmap_base;
    } else if ((bpos = it->find("bitmap: ")) != std::string::npos) {
      bitmap = it->substr(bpos + 8);
    }
  }

  if (flags != 0xFFFF && !reader_id.empty() && !writer_id.empty()) {
    rtps_acknack acknack;
    acknack.flags = flags;
    acknack.reader_id = reader_id;
    acknack.writer_id = writer_id;
    acknack.bitmap_base = bitmap_base;
    acknack.bitmap = bitmap;
    acknack.sm_order = sm_order;
    frame.acknack_vec.push_back(acknack);
    result = true;
  }
  return result;
}

bool process_rtps_submessage(const string_vec& rtps_submessage, rtps_frame& frame, size_t sm_order)
{
  bool result = false;
  if (rtps_submessage.size() != 0) {
    size_t spos;
    if ((spos = rtps_submessage.front().find("submessageId: ")) != std::string::npos) {
      std::string sm_type = rtps_submessage.front().substr(spos + 14);
      sm_type = sm_type.substr(0, sm_type.find(" "));
      //std::cout << sm_type << std::endl;
      if (sm_type == "INFO_DST") {
        result = process_rtps_info_dst_submessage(rtps_submessage, frame, sm_order);
      } else if (sm_type == "DATA") {
        result = process_rtps_data_submessage(rtps_submessage, frame, sm_order);
      } else if (sm_type == "GAP") {
        result = process_rtps_gap_submessage(rtps_submessage, frame, sm_order);
      } else if (sm_type == "HEARTBEAT") {
        result = process_rtps_heartbeat_submessage(rtps_submessage, frame, sm_order);
      } else if (sm_type == "ACKNACK") {
        result = process_rtps_acknack_submessage(rtps_submessage, frame, sm_order);
      } else {
        result = true;
      }
    }
  }
  return result;
}

bool process_rtps_submessages(const std::vector<string_vec>& rtps_submessages, rtps_frame& frame) {
  bool result = true;
  size_t sm_order = 0;
  for (auto it = rtps_submessages.begin(); result && it != rtps_submessages.end(); ++it) {
    result &= process_rtps_submessage(*it, frame, sm_order++);
  }
  return result;
}

void process_frame(const string_vec& frame_data, std::map<size_t, rtps_frame>& frames, ip_frag_map& ifm) {

  string_vec frame_header;
  string_vec eth_header;
  string_vec ip_header;
  string_vec udp_header;
  string_vec rtps_header;
  std::vector<string_vec> rtps_submessages;

  for (auto it = frame_data.begin(); it != frame_data.end(); ++it) {
    if (eth_header.size() == 0 && it->substr(0, 8) != "Ethernet" && *it != "Linux cooked capture") {
      frame_header.push_back(*it);
    } else if (ip_header.size() == 0 && it->substr(0, 17) != "Internet Protocol") {
      eth_header.push_back(*it);
    } else if (udp_header.size() == 0 && it->substr(0, 22) != "User Datagram Protocol") {
      ip_header.push_back(*it);
    } else if (rtps_header.size() == 0 && it->substr(0, 41) != "Real-Time Publish-Subscribe Wire Protocol") {
      udp_header.push_back(*it);
    } else if (rtps_submessages.size() == 0 && it->find("submessageId:") == std::string::npos) {
      rtps_header.push_back(*it);
    } else if (it->find("submessageId:") != std::string::npos) {
      rtps_submessages.push_back(string_vec());
      rtps_submessages.back().push_back(*it);
    } else {
      rtps_submessages.back().push_back(*it);
    }
  }

  /*
  // Some debugging output for section sizes
  std::cout << frame_header.size() << " " << eth_header.size() << " " << ip_header.size() << " " << udp_header.size() << " " << rtps_header.size() << std::flush;
  if (rtps_submessages.size()) {
    std::cout << " (" << std::flush;
    for (auto it = rtps_submessages.begin(); it != rtps_submessages.end(); ++it) {
      if (it != rtps_submessages.begin()) {
        std::cout << ", " << std::flush;
      }
      std::cout << it->size() << std::flush;
    }
    std::cout << ")" << std::flush;
  }
  std::cout << std::endl;
  */

  rtps_frame frame;
  frame.frame_no = 0;
  if (process_frame_header(frame_header, frame) &&
      process_eth_header(eth_header, frame) &&
      process_ip_header(ip_header, frame, ifm) &&
      process_udp_header(udp_header, frame))
  {
    if (process_rtps_header(rtps_header, frame) &&
        process_rtps_submessages(rtps_submessages, frame))
    {
      //std::cout << "successfully processed frame " << frame.frame_no << std::endl;
      frames[frame.frame_no] = frame;
    }
    else
    {
      std::cout << "error processing frame " << frame.frame_no << std::endl;
    }
  }
  else
  {
    //std::cout << "encountered issue, skipping frame" << frame.frame_no << std::endl;
  }
}

void process_frame_data(const std::map<size_t, string_vec>& frame_data, std::map<size_t, rtps_frame>& frames, ip_frag_map& ifm) {
  for (auto it = frame_data.begin(); it != frame_data.end(); ++it) {
    process_frame(it->second, frames, ifm);
  }
}

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

bool create_or_merge_net_info(const net_info& info, std::map<std::string, net_info>& nm) {
  auto it = nm.find(info.ip);
  if (it != nm.end()) {
    return merge_net_info(it->second, info);
  } else {
    nm[info.ip] = info;
    return true;
  }
}

std::vector<rtps_info_dst>::const_iterator find_previous_dst(const rtps_frame& frame, size_t sm_order_limit) {
  std::vector<rtps_info_dst>::const_iterator old = frame.info_dst_vec.end();
  std::vector<rtps_info_dst>::const_iterator pos = frame.info_dst_vec.begin();
  while (pos != frame.info_dst_vec.end() && pos->sm_order < sm_order_limit) {
    old = pos;
    ++pos;
  }
  return old;
}

void filter_spdp_announcements(const std::vector<std::pair<const rtps_frame*, const rtps_data*>>& in, size_t fnum, const std::string& wguid, const std::string& rguid, std::vector<std::pair<const rtps_frame*, const rtps_data*>>& out);
void filter_spdp_announcements(const std::vector<std::pair<const rtps_frame*, const rtps_data*>>& in, size_t fnum, const std::string& wguid, const std::string& rguid, std::vector<std::pair<const rtps_frame*, const rtps_data*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    if (v.first->frame_no >= fnum) {
      if (!v.second->participant_guid.empty()) {
        if (v.second->participant_guid.substr(0, 24) == wguid.substr(0, 24) || v.second->participant_guid.substr(0, 24) == rguid.substr(0, 24)) {
          out.push_back(v);
        }
      }
    }
  });
}

void filter_sedp_announcements(const std::vector<std::pair<const rtps_frame*, const rtps_data*>>& in, size_t fnum, const std::string& wguid, const std::string& rguid, std::vector<std::pair<const rtps_frame*, const rtps_data*>>& out);
void filter_sedp_announcements(const std::vector<std::pair<const rtps_frame*, const rtps_data*>>& in, size_t fnum, const std::string& wguid, const std::string& rguid, std::vector<std::pair<const rtps_frame*, const rtps_data*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    if (v.first->frame_no >= fnum) {
      if (!v.second->endpoint_guid.empty()) {
        if (v.second->endpoint_guid == wguid || v.second->endpoint_guid == rguid) {
          out.push_back(v);
        }
      }
    }
  });
}

template <typename T>
void filter_info_pair_vec_by_frame_and_reader_dst(const std::vector<std::pair<const rtps_frame*, const T*>>& in, size_t fnum, const std::string& guid, const std::map<std::string, net_info>& nm, std::vector<std::pair<const rtps_frame*, const T*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    std::vector<rtps_info_dst>::const_iterator idit;
    if ((idit = find_previous_dst(*(v.first), v.second->sm_order)) != v.first->info_dst_vec.end()) {
      if (guid != (idit->guid_prefix + v.second->reader_id)) {
        return;
      }
    }
    if (v.first->frame_no >= fnum) {
      if (v.second->reader_id == "00000000" || v.second->reader_id == guid.substr(24, 8)) {
        auto it = nm.find(v.first->dst_ip);
        if (it != nm.end()) {
          out.push_back(v);
        }
      }
    }
  });
}

template <typename T>
void filter_info_pair_vec_by_frame_and_reader_dst_full(const std::vector<std::pair<const rtps_frame*, const T*>>& in, size_t fnum, const std::string& guid, const std::map<std::string, net_info>& nm, std::vector<std::pair<const rtps_frame*, const T*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    std::vector<rtps_info_dst>::const_iterator idit;
    if ((idit = find_previous_dst(*(v.first), v.second->sm_order)) != v.first->info_dst_vec.end()) {
      if (guid != (idit->guid_prefix + v.second->reader_id)) {
        return;
      }
    }
    if (v.first->frame_no >= fnum) {
      if (v.second->reader_id == "00000000" || v.second->reader_id == guid.substr(24, 8)) {
        auto it = nm.find(v.first->dst_ip);
        if (it != nm.end()) {
          if ((it->second.mac != "" && it->second.mac != v.first->dst_mac) || (it->second.port != "" && it->second.port != v.first->dst_port)) {
            //std::cout << "filtering dst by mac and port makes a difference!" << std::endl;
          } else {
            out.push_back(v);
          }
        }
      }
    }
  });
}

template <typename T>
void filter_info_pair_vec_by_frame_and_writer_dst_full(const std::vector<std::pair<const rtps_frame*, const T*>>& in, size_t fnum, const std::string& guid, const std::map<std::string, net_info>& nm, std::vector<std::pair<const rtps_frame*, const T*>>& out) {
  std::for_each(in.begin(), in.end(), [&](const auto& v) {
    std::vector<rtps_info_dst>::const_iterator idit;
    if ((idit = find_previous_dst(*(v.first), v.second->sm_order)) != v.first->info_dst_vec.end()) {
      if (guid != (idit->guid_prefix + v.second->writer_id)) {
        return;
      }
    }
    if (v.first->frame_no >= fnum) {
      if (v.second->writer_id == "00000000" || v.second->writer_id == guid.substr(24, 8)) {
        auto it = nm.find(v.first->dst_ip);
        if (it != nm.end()) {
          if ((it->second.mac != "" && it->second.mac != v.first->dst_mac) || (it->second.port != "" && it->second.port != v.first->dst_port)) {
            //std::cout << "filtering dst by mac and port makes a difference!" << std::endl;
          } else {
            out.push_back(v);
          }
        }
      }
    }
  });
}

bool merge_endpoint_info(endpoint_info& existing, const endpoint_info& update) {
  bool result = true;

  if (!merge_net_info(existing.src_net, update.src_net)) {
    std::cout << "Issues merging source network info for endpoint " << existing.guid << std::endl;
    result = false;
  }

  std::for_each(update.dst_net_map.begin(), update.dst_net_map.end(), [&](const auto& v) {
    if (!create_or_merge_net_info(v.second, existing.dst_net_map)) {
      std::cout << "Issues merging destination network info for endpoint " << existing.guid << std::endl;
      result = false;
    }
  });

  if (existing.domain_id == 0xFF) {
    existing.domain_id = update.domain_id;
  }

  existing.reliable.merge(update.reliable);

  existing.spdp_announcements.insert(existing.spdp_announcements.end(), update.spdp_announcements.begin(), update.spdp_announcements.end());
  existing.sedp_announcements.insert(existing.sedp_announcements.end(), update.sedp_announcements.begin(), update.sedp_announcements.end());
  existing.datas.insert(existing.datas.end(), update.datas.begin(), update.datas.end());
  existing.gaps.insert(existing.gaps.end(), update.gaps.begin(), update.gaps.end());
  existing.heartbeats.insert(existing.heartbeats.end(), update.heartbeats.begin(), update.heartbeats.end());
  existing.acknacks.insert(existing.acknacks.end(), update.acknacks.begin(), update.acknacks.end());

  if (existing.domain_id != update.domain_id && update.domain_id != 0xFF) {
    std::cout << "Contradictory endpoint data found while merging entries for GUID " << update.guid << std::endl;
    std::cout << "Existing Info: " << existing << std::endl;
    std::cout << "Update   Info: " << update << std::endl;
    result = false;
  }
  return result;
}

bool create_or_merge_endpoint_info(const endpoint_info& info, endpoint_map& em) {
  auto it = em.find(info.guid);
  if (it != em.end()) {
    return merge_endpoint_info(it->second, info);
  } else {
    em[info.guid] = info;
    return true;
  }
}

void gather_participant_info(const std::map<size_t, rtps_frame>& frames, endpoint_map& em) {
  for (auto fit = frames.begin(); fit != frames.end(); ++fit) {
    for (auto dit = fit->second.data_vec.begin(); dit != fit->second.data_vec.end(); ++dit) {
      if (dit->writer_id == "000100c2") {
        endpoint_info info;
        info.src_net = { fit->second.src_mac, fit->second.src_ip, fit->second.src_port };
        info.first_evidence_frame = fit->second.frame_no;
        info.first_evidence_time = fit->second.frame_reference_time;
        info.reliable = false;
        info.guid = fit->second.guid_prefix + dit->writer_id;

        uint16_t port = 0;
        std::stringstream ss(fit->second.dst_port);
        ss >> port;
        info.domain_id = (port < 7400 ? 0xFF : static_cast<uint16_t>(port - 7400) / 250);

        create_or_merge_endpoint_info(info, em);
      }
    }
  }
}

void gather_endpoint_info(const std::map<size_t, rtps_frame>& frames, endpoint_map& em) {
  for (auto fit = frames.begin(); fit != frames.end(); ++fit) {
    endpoint_info info;
    info.src_net = { fit->second.src_mac, fit->second.src_ip, fit->second.src_port };
    auto pit = em.find(fit->second.guid_prefix + "000100c2");
    if (pit != em.end()) {
      info.domain_id = pit->second.domain_id;
    }
    info.first_evidence_frame = fit->second.frame_no;
    info.first_evidence_time = fit->second.frame_reference_time;

    for (auto dit = fit->second.data_vec.begin(); dit != fit->second.data_vec.end(); ++dit) {
      endpoint_info dataw_info(info);
      dataw_info.guid = fit->second.guid_prefix + dit->writer_id;
      if (!dit->participant_guid.empty()) {
        endpoint_info spdp_info;
        for (size_t i = 0; i < dit->metatraffic_unicast_locator_ips.size(); ++i)
          create_or_merge_net_info(net_info("", dit->metatraffic_unicast_locator_ips[i], dit->metatraffic_unicast_locator_ports[i]), spdp_info.dst_net_map);
        for (size_t i = 0; i < dit->metatraffic_multicast_locator_ips.size(); ++i)
          create_or_merge_net_info(net_info("", dit->metatraffic_multicast_locator_ips[i], dit->metatraffic_multicast_locator_ports[i]), spdp_info.dst_net_map);
        spdp_info.first_evidence_frame = dataw_info.first_evidence_frame;
        spdp_info.first_evidence_time = dataw_info.first_evidence_time;
        spdp_info.spdp_announcements.emplace_back(data_info_pair(&(fit->second), &(*dit)));

        spdp_info.guid = dit->participant_guid.substr(0, 24) + "000100c2"; // Participant Writer
        spdp_info.reliable = false;
        create_or_merge_endpoint_info(spdp_info, em);

        spdp_info.guid = dit->participant_guid.substr(0, 24) + "000100c7"; // Participant Reader
        spdp_info.reliable = false;
        create_or_merge_endpoint_info(spdp_info, em);

        spdp_info.guid = dit->participant_guid.substr(0, 24) + "000003c2"; // Publications Writer
        spdp_info.reliable = true;
        create_or_merge_endpoint_info(spdp_info, em);

        spdp_info.guid = dit->participant_guid.substr(0, 24) + "000003c7"; // Publications Reader
        spdp_info.reliable = true;
        create_or_merge_endpoint_info(spdp_info, em);

        spdp_info.guid = dit->participant_guid.substr(0, 24) + "000004c2"; // Subscriptions Writer
        spdp_info.reliable = true;
        create_or_merge_endpoint_info(spdp_info, em);

        spdp_info.guid = dit->participant_guid.substr(0, 24) + "000004c7"; // Subscriptions Reader
        spdp_info.reliable = true;
        create_or_merge_endpoint_info(spdp_info, em);

        spdp_info.guid = dit->participant_guid.substr(0, 24) + "000200c2"; // Participant Message Writer
        spdp_info.reliable = true;
        create_or_merge_endpoint_info(spdp_info, em);

        spdp_info.guid = dit->participant_guid.substr(0, 24) + "000200c7"; // Participant Message Reader
        spdp_info.reliable = true;
        create_or_merge_endpoint_info(spdp_info, em);
      }
      if (!dit->endpoint_guid.empty()) {
        endpoint_info sedp_info;
        sedp_info.guid = dit->endpoint_guid;
        for (size_t i = 0; i < dit->unicast_locator_ips.size(); ++i)
          create_or_merge_net_info(net_info("", dit->unicast_locator_ips[i], dit->unicast_locator_ports[i]), sedp_info.dst_net_map);
        for (size_t i = 0; i < dit->multicast_locator_ips.size(); ++i)
          create_or_merge_net_info(net_info("", dit->multicast_locator_ips[i], dit->multicast_locator_ports[i]), sedp_info.dst_net_map);
        sedp_info.domain_id = dataw_info.domain_id;
        sedp_info.first_evidence_frame = dataw_info.first_evidence_frame;
        sedp_info.first_evidence_time = dataw_info.first_evidence_time;
        sedp_info.sedp_announcements.emplace_back(data_info_pair(&(fit->second), &(*dit)));
        sedp_info.reliable = dit->endpoint_reliability;
        if (dit->writer_id == "000003c2") {
          //std::cout << "writer announcment: " << sedp_info.guid << std::endl;
        } else if (dit->writer_id == "000004c2") {
          //std::cout << "reader announcment: " << sedp_info.guid << std::endl;
        }
        create_or_merge_endpoint_info(sedp_info, em);
        if (dit->writer_id == "000004c2") {
          for (auto it = dit->registered_writers.begin(); it != dit->registered_writers.end(); ++it) {
            endpoint_info rw_info;
            rw_info.guid = *it;
            rw_info.domain_id = dataw_info.domain_id;
            rw_info.first_evidence_frame = dataw_info.first_evidence_frame;
            rw_info.first_evidence_time = dataw_info.first_evidence_time;
            rw_info.sedp_announcements.emplace_back(data_info_pair(&(fit->second), &(*dit)));
            create_or_merge_endpoint_info(rw_info, em);
          }
        }
      }
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(fit->second, dit->sm_order)) != fit->second.info_dst_vec.end() && dit->reader_id != "00000000") {
        endpoint_info datar_info;
        datar_info.guid = idit->guid_prefix + dit->reader_id;
        create_or_merge_net_info(net_info(fit->second.dst_mac, fit->second.dst_ip, fit->second.dst_port), datar_info.dst_net_map);
        datar_info.domain_id = dataw_info.domain_id;
        datar_info.first_evidence_frame = dataw_info.first_evidence_frame;
        datar_info.first_evidence_time = dataw_info.first_evidence_time;
        create_or_merge_endpoint_info(datar_info, em);
      } else {
        dataw_info.datas.emplace_back(data_info_pair(&(fit->second), &(*dit)));
      }
      create_or_merge_endpoint_info(dataw_info, em);
    }
    for (auto git = fit->second.gap_vec.begin(); git != fit->second.gap_vec.end(); ++git) {
      endpoint_info gapw_info(info);
      gapw_info.guid = fit->second.guid_prefix + git->writer_id;
      //gapw_info.reliable = true; // TODO Is this correct?
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(fit->second, git->sm_order)) != fit->second.info_dst_vec.end() && git->reader_id != "00000000") {
        endpoint_info gapr_info;
        gapr_info.guid = idit->guid_prefix + git->reader_id;
        if (fit->second.info_dst_vec.size() == 1) {
          // We do this to handle the weird durabile writer gap split & resend-to-all-locators issue which sometimes gives us gaps with wrong ip/udp dst info
          create_or_merge_net_info(net_info(fit->second.dst_mac, fit->second.dst_ip, fit->second.dst_port), gapr_info.dst_net_map);
        }
        gapr_info.domain_id = gapw_info.domain_id;
        gapr_info.first_evidence_frame = gapw_info.first_evidence_frame;
        gapr_info.first_evidence_time = gapw_info.first_evidence_time;
        //gapr_info.reliable = true; // TODO Is this correct?
        create_or_merge_endpoint_info(gapr_info, em);
      } else {
        gapw_info.gaps.emplace_back(gap_info_pair(&(fit->second), &(*git)));
      }
      create_or_merge_endpoint_info(gapw_info, em);
    }
    for (auto hit = fit->second.heartbeat_vec.begin(); hit != fit->second.heartbeat_vec.end(); ++hit) {
      endpoint_info hbw_info(info);
      hbw_info.guid = fit->second.guid_prefix + hit->writer_id;
      //hbw_info.reliable = true; // TODO Is this correct?
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(fit->second, hit->sm_order)) != fit->second.info_dst_vec.end() && hit->reader_id != "00000000") {
        endpoint_info hbr_info;
        hbr_info.guid = idit->guid_prefix + hit->reader_id;
        create_or_merge_net_info(net_info(fit->second.dst_mac, fit->second.dst_ip, fit->second.dst_port), hbr_info.dst_net_map);
        hbr_info.domain_id = hbw_info.domain_id;
        hbr_info.first_evidence_frame = hbw_info.first_evidence_frame;
        hbr_info.first_evidence_time = hbw_info.first_evidence_time;
        //hbr_info.reliable = true; // TODO Is this correct?
        create_or_merge_endpoint_info(hbr_info, em);
      } else {
        hbw_info.heartbeats.emplace_back(hb_info_pair(&(fit->second), &(*hit)));
      }
      create_or_merge_endpoint_info(hbw_info, em);
    }
    for (auto ait = fit->second.acknack_vec.begin(); ait != fit->second.acknack_vec.end(); ++ait) {
      endpoint_info anr_info(info);
      anr_info.guid = fit->second.guid_prefix + ait->reader_id; // acknack comes from reader side
      anr_info.reliable = true;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(fit->second, ait->sm_order)) != fit->second.info_dst_vec.end() && ait->writer_id != "00000000") {
        endpoint_info anw_info;
        anw_info.guid = idit->guid_prefix + ait->writer_id; // but also tells us about writer side
        create_or_merge_net_info(net_info(fit->second.dst_mac, fit->second.dst_ip, fit->second.dst_port), anw_info.dst_net_map);
        anw_info.domain_id = anr_info.domain_id;
        anw_info.first_evidence_frame = anr_info.first_evidence_frame;
        anw_info.first_evidence_time = anr_info.first_evidence_time;
        anw_info.reliable = true;
        create_or_merge_endpoint_info(anw_info, em);
      } else {
        anr_info.acknacks.emplace_back(an_info_pair(&(fit->second), &(*ait)));
      }
      create_or_merge_endpoint_info(anr_info, em);
    }
  }
}

void copy_endpoint_details_relevant_to_conversation(const endpoint_info& writer, const endpoint_info& reader, const endpoint_map& em, conversation_info& conv);
void copy_endpoint_details_relevant_to_conversation(const endpoint_info& writer, const endpoint_info& reader, const endpoint_map& em, conversation_info& conv) {
  size_t first_first_frame = reader.first_evidence_frame < writer.first_evidence_frame ? reader.first_evidence_frame : writer.first_evidence_frame;
  auto wpartrit = em.find(writer.guid.substr(0, 24) + "000100c7");
  auto rpartrit = em.find(reader.guid.substr(0, 24) + "000100c7");
  auto wsubrit = em.find(writer.guid.substr(0, 24) + "000004c7");
  auto rpubrit = em.find(reader.guid.substr(0, 24) + "000003c7");

  if (wpartrit == em.end()) {
    std::cout << "This shouldn't happen! Participant reader for writer " << writer.guid << " doesn't show up in endpoint map." << std::endl;
  } else if (rpartrit == em.end()) {
    std::cout << "This shouldn't happen! Participant reader for reader" << reader.guid << " doesn't show up in endpoint map." << std::endl;
  } else if (wsubrit == em.end()) {
    std::cout << "This shouldn't happen! Subscriptions reader for writer " << writer.guid << " doesn't show up in endpoint map." << std::endl;
  } else if (rpubrit == em.end()) {
    std::cout << "This shouldn't happen! Publications reader for reader " << reader.guid << " doesn't show up in endpoint map." << std::endl;
  } else {
    std::vector<data_info_pair> spdp_datas;
    filter_spdp_announcements(writer.spdp_announcements, first_first_frame, conv.writer_guid, conv.reader_guid, spdp_datas);
    filter_spdp_announcements(reader.spdp_announcements, first_first_frame, conv.writer_guid, conv.reader_guid, spdp_datas);
    conv.datas = spdp_datas;

    std::vector<data_info_pair> sedp_datas;
    filter_info_pair_vec_by_frame_and_reader_dst_full(writer.sedp_announcements, first_first_frame, reader.guid.substr(0, 24) + "000003c7", rpubrit->second.dst_net_map, sedp_datas);
    filter_info_pair_vec_by_frame_and_reader_dst_full(reader.sedp_announcements, first_first_frame, writer.guid.substr(0, 24) + "000004c7", wsubrit->second.dst_net_map, sedp_datas);
    filter_sedp_announcements(sedp_datas, first_first_frame, conv.writer_guid, conv.reader_guid, conv.datas);
  }
  filter_info_pair_vec_by_frame_and_reader_dst_full(writer.datas, reader.first_evidence_frame, conv.reader_guid, reader.dst_net_map, conv.datas);
  filter_info_pair_vec_by_frame_and_reader_dst_full(writer.gaps, reader.first_evidence_frame, conv.reader_guid, reader.dst_net_map, conv.gaps);
  filter_info_pair_vec_by_frame_and_reader_dst_full(writer.heartbeats, reader.first_evidence_frame, conv.reader_guid, reader.dst_net_map, conv.heartbeats);
  filter_info_pair_vec_by_frame_and_writer_dst_full(reader.acknacks, writer.first_evidence_frame, conv.writer_guid, writer.dst_net_map, conv.acknacks);
}

void gather_conversation_info(const std::map<size_t, rtps_frame>& frames, const endpoint_map& em, conversation_map& cm) {
  for (auto fit = frames.begin(); fit != frames.end(); ++fit) {
    conversation_info info;
    info.domain_id = fit->second.domain_id;
    info.first_evidence_frame = fit->second.frame_no;
    info.first_evidence_time = fit->second.frame_reference_time;
    for (auto dit = fit->second.data_vec.begin(); dit != fit->second.data_vec.end(); ++dit) {
      info.writer_guid = fit->second.guid_prefix + dit->writer_id;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(fit->second, dit->sm_order)) != fit->second.info_dst_vec.end()) {
        const rtps_info_dst& dst = *idit;
        info.reader_guid = dst.guid_prefix + dit->reader_id;
        auto weit = em.find(info.writer_guid);
        auto reit = em.find(info.reader_guid);
        if (weit == em.end()) {
          std::cout << "This shouldn't happen! Data writer " << info.writer_guid << " doesn't show up in endpoint map." << std::endl;
        } else if (reit == em.end()) {
          std::cout << "This shouldn't happen! Data reader " << info.reader_guid << " doesn't show up in endpoint map." << std::endl;
        } else {
          auto wcit = cm.find(info.writer_guid);
          if (wcit == cm.end()) {
            copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
            info.datas.emplace_back(data_info_pair(&(fit->second), &(*dit)));
            cm[info.writer_guid][info.reader_guid] = info;
          } else {
            auto rcit = wcit->second.find(info.reader_guid);
            if (rcit == wcit->second.end()) {
              copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
              info.datas.emplace_back(data_info_pair(&(fit->second), &(*dit)));
              wcit->second[info.reader_guid] = info;
            } else {
              rcit->second.datas.emplace_back(data_info_pair(&(fit->second), &(*dit)));
            }
          }
        }
      } else {
        if (dit->writer_id == "000004c2" && !dit->endpoint_guid.empty()) {
          for (auto it = dit->registered_writers.begin(); it != dit->registered_writers.end(); ++it) {
            info.writer_guid = *it;
            info.reader_guid = dit->endpoint_guid;
            auto weit = em.find(info.writer_guid);
            auto reit = em.find(info.reader_guid);
            if (weit == em.end()) {
              std::cout << "This shouldn't happen! Registered writer " << info.writer_guid << " doesn't show up in endpoint map." << std::endl;
            } else if (reit == em.end()) {
              std::cout << "This shouldn't happen! Announced reader " << info.reader_guid << " doesn't show up in endpoint map." << std::endl;
            } else {
              auto wcit = cm.find(info.writer_guid);
              if (wcit == cm.end()) {
                copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
                cm[info.writer_guid][info.reader_guid] = info;
              } else {
                auto rcit = wcit->second.find(info.reader_guid);
                if (rcit == wcit->second.end()) {
                  copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
                  wcit->second[info.reader_guid] = info;
                } else {
                  // Do nothing, we might see the same reader announcement several times with old + new registered writers
                }
              }
            }
          }
        }
      }
    }
    for (auto git = fit->second.gap_vec.begin(); git != fit->second.gap_vec.end(); ++git) {
      info.writer_guid = fit->second.guid_prefix + git->writer_id;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(fit->second, git->sm_order)) != fit->second.info_dst_vec.end()) {
        const rtps_info_dst& dst = *idit;
        info.reader_guid = dst.guid_prefix + git->reader_id;
        auto weit = em.find(info.writer_guid);
        auto reit = em.find(info.reader_guid);
        if (weit == em.end()) {
          std::cout << "This shouldn't happen! Gap writer " << info.writer_guid << " doesn't show up in endpoint map." << std::endl;
        } else if (reit == em.end()) {
          std::cout << "This shouldn't happen! Gap reader " << info.reader_guid << " doesn't show up in endpoint map." << std::endl;
        } else {
          auto wcit = cm.find(info.writer_guid);
          if (wcit == cm.end()) {
            copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
            info.gaps.emplace_back(gap_info_pair(&(fit->second), &(*git)));
            cm[info.writer_guid][info.reader_guid] = info;
          } else {
            auto rcit = wcit->second.find(info.reader_guid);
            if (rcit == wcit->second.end()) {
              copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
              info.gaps.emplace_back(gap_info_pair(&(fit->second), &(*git)));
              wcit->second[info.reader_guid] = info;
            } else {
              rcit->second.gaps.emplace_back(gap_info_pair(&(fit->second), &(*git)));
            }
          }
        }
      }
    }
    for (auto hit = fit->second.heartbeat_vec.begin(); hit != fit->second.heartbeat_vec.end(); ++hit) {
      info.writer_guid = fit->second.guid_prefix + hit->writer_id;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(fit->second, hit->sm_order)) != fit->second.info_dst_vec.end()) {
        const rtps_info_dst& dst = *idit;
        info.reader_guid = dst.guid_prefix + hit->reader_id;
        auto weit = em.find(info.writer_guid);
        auto reit = em.find(info.reader_guid);
        if (weit == em.end()) {
          std::cout << "This shouldn't happen! Heartbeat writer " << info.writer_guid << " doesn't show up in endpoint map." << std::endl;
        } else if (reit == em.end()) {
          std::cout << "This shouldn't happen! Heartbeat reader " << info.reader_guid << " doesn't show up in endpoint map." << std::endl;
        } else {
          auto wcit = cm.find(info.writer_guid);
          if (wcit == cm.end()) {
            copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
            info.heartbeats.emplace_back(hb_info_pair(&(fit->second), &(*hit)));
            cm[info.writer_guid][info.reader_guid] = info;
          } else {
            auto rcit = wcit->second.find(info.reader_guid);
            if (rcit == wcit->second.end()) {
              copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
              info.heartbeats.emplace_back(hb_info_pair(&(fit->second), &(*hit)));
              wcit->second[info.reader_guid] = info;
            } else {
              rcit->second.heartbeats.emplace_back(hb_info_pair(&(fit->second), &(*hit)));
            }
          }
        }
      }
    }
    for (auto ait = fit->second.acknack_vec.begin(); ait != fit->second.acknack_vec.end(); ++ait) {
      info.reader_guid = fit->second.guid_prefix + ait->reader_id;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(fit->second, ait->sm_order)) != fit->second.info_dst_vec.end()) {
        const rtps_info_dst& dst = *idit;
        info.writer_guid = dst.guid_prefix + ait->writer_id;
        auto weit = em.find(info.writer_guid);
        auto reit = em.find(info.reader_guid);
        if (weit == em.end()) {
          std::cout << "This shouldn't happen! Acknack writer " << info.writer_guid << " doesn't show up in endpoint map." << std::endl;
        } else if (reit == em.end()) {
          std::cout << "This shouldn't happen! Acknack reader " << info.reader_guid << " doesn't show up in endpoint map." << std::endl;
        } else {
          auto wcit = cm.find(info.writer_guid);
          if (wcit == cm.end()) {
            copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
            info.acknacks.emplace_back(an_info_pair(&(fit->second), &(*ait)));
            cm[info.writer_guid][info.reader_guid] = info;
          } else {
            auto rcit = wcit->second.find(info.reader_guid);
            if (rcit == wcit->second.end()) {
              copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
              info.acknacks.emplace_back(an_info_pair(&(fit->second), &(*ait)));
              wcit->second[info.reader_guid] = info;
            } else {
              rcit->second.acknacks.emplace_back(an_info_pair(&(fit->second), &(*ait)));
            }
          }
        }
      }
    }
  }
}

bool is_id_builtin(const std::string& id);
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

bool is_guid_builtin(const std::string& guid);
bool is_guid_builtin(const std::string& guid) {
  return is_id_builtin(guid.substr(24, 8));
}

int main(int argc, char** argv)
{
  // Declare the supported options.
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help", "produce help message")
    ("file", po::value<std::string>(), "input filename")
    ("show-participants", "show participant information")
    ("show-endpoints", "show endpoint information")
    ("show-conversations", "show conversation information")
    ("show-undiscovered", "show potentially 'undiscovered' endpoint information")
    ("show-discovery-times", "show discovery times for conversations")
    ("domain", po::value<uint16_t>(), "domain to examine")
    ("show-conversation-frames", po::value<string_vec>(), "show frames relevant to conversation between two guids (as: '<guid1>,<guid2>')")
    //("guid", po::value<string_vec>(), "guid to examine") // TODO Add support for filtering by guid eventually?
  ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << desc << "\n";
    return 1;
  }

  std::string filename;
  if (vm.count("file")) {
    filename = vm["file"].as<std::string>();
    std::cout << "Using file: " << vm["file"].as<std::string>() << std::endl;
  } else {
    std::cout << "Input file was not set.\n";
    return 1;
  }

  std::ifstream ifs(filename.c_str());

  if (!ifs.good()) {
    std::cout << "Unable to open input file " << filename << std::endl;
    return 1;
  }

  uint16_t domain = 0xFF;
  if (vm.count("domain")) {
    domain = vm["domain"].as<uint16_t>();
  }

  /*
  // TODO Add support for filtering by guid eventually?
  string_vec guids;
  if (vm.count("guid")) {
    guids = vm["guid"].as<string_vec>();
    for (auto it = guids.begin(); it != guids.end(); ++it) {
      std::cout << "tracking guid: " << *it << std::endl;
    }
  }
  */

  std::map<size_t, string_vec> frame_data;

  std::string line;
  std::getline(ifs, line);
  size_t frame_no = 0;
  while (ifs.good()) {
    if (line.substr(0, 6) == "Frame ") {
      std::stringstream ss(line.substr(6, line.find(":")));
      ss >> frame_no;
      //std::cout << "Found header for frame " << frame << std::endl;
    }
    frame_data[frame_no].push_back(line);
    std::getline(ifs, line);
  }

  std::map<size_t, rtps_frame> frames;
  ip_frag_map ifm;
  process_frame_data(frame_data, frames, ifm);

  endpoint_map em;
  gather_participant_info(frames, em);
  gather_endpoint_info(frames, em);

  // Display Endpoint Info
  if (vm.count("show-endpoints")) {
    std::cout << "Endpoint Info:" << std::endl;
    for (auto it = em.begin(); it != em.end(); ++it) {
      if (domain == 0xFF || domain == it->second.domain_id) {
        std::cout << it->second << std::endl;
      }
    }
  }

  std::set<std::string> participant_guids;
  std::set<std::string> userdata_endpoint_guids;
  double last_participant_time = 0.0;
  double last_userdata_endpoint_time = 0.0;
  for (auto it = frames.begin(); it != frames.end(); ++it) {
    if (it->second.data_vec.size()) {
      if (domain == 0xFF || domain == it->second.domain_id) {
        if (!it->second.data_vec.front().participant_guid.empty()) {
          if (participant_guids.insert(it->second.data_vec.front().participant_guid).second) {
            last_participant_time = it->second.frame_reference_time;
          }
        }
        if (!it->second.data_vec.front().endpoint_guid.empty()) {
          if (userdata_endpoint_guids.insert(it->second.data_vec.front().endpoint_guid).second) {
            last_userdata_endpoint_time = it->second.frame_reference_time;
          }
        }
      }
    }
  }

  if (vm.count("show-participants")) {
    std::cout << "Participant guids:" << std::endl;
    for (auto it = participant_guids.begin(); it != participant_guids.end(); ++it) {
      std::cout << *it << std::endl;
    }
  }

  conversation_map cm;
  gather_conversation_info(frames, em, cm);

  std::set<std::string> conversation_guids;
  if (vm.count("show-conversations")) {
    std::cout << "Conversations Info:" << std::endl;
  }
  for (auto it = cm.begin(); it != cm.end(); ++it) {
    for (auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
      if (domain == 0xFF || domain == it2->second.domain_id) {
        conversation_guids.insert(it2->second.writer_guid);
        conversation_guids.insert(it2->second.reader_guid);
        if (vm.count("show-conversations")) {
          std::cout << "Conversation found: " << it2->second.writer_guid << " >> " << it2->second.reader_guid << " @ " << it2->second.first_evidence_time << std::endl;
        }
      }
    }
  }

  if (vm.count("show-conversation-frames")) {
    string_vec clist = vm["show-conversation-frames"].as<string_vec>();
    for (auto it = clist.begin(); it != clist.end(); ++it) {
      size_t cpos = 0;
      if (it->length() != 65 || (cpos = it->find(",") != 32)) {
        std::cout << "error parsing conversation! cpos = " << cpos << std::endl;
        continue;
      }
      std::string guid1 = it->substr(0, 32);
      std::string guid2 = it->substr(33, 32);
      std::string writer_guid;
      std::string reader_guid;
      if (guid1[guid1.length() - 1] == '2' && guid2[guid2.length() - 1] == '7') {
        writer_guid = guid1;
        reader_guid = guid2;
      } else if (guid1[guid1.length() - 1] == '7' && guid2[guid2.length() - 1] == '2') {
        writer_guid = guid2;
        reader_guid = guid1;
      } else {
        std::cout << "not a conversation! needs one writer and one reader" << std::endl;
        continue;
      }
      auto wit = em.find(writer_guid);
      if (wit == em.end()) {
        std::cout << "unable to find writer in endpoint map!" << std::endl;
        continue;
      }
      auto rit = em.find(reader_guid);
      if (rit == em.end()) {
        std::cout << "unable to find reader in endpoint map!" << std::endl;
        continue;
      }
      auto cit1 = cm.find(writer_guid);
      if (cit1 == cm.end()) {
        std::cout << "unable to find writer in conversation map!" << std::endl;
        continue;
      }
      auto cit2 = cit1->second.find(reader_guid);
      if (cit2 == cit1->second.end()) {
        std::cout << "unable to find reader in conversation map!" << std::endl;
        continue;
      }
      const auto& cinfo = cit2->second;
      std::set<size_t> cframes;
      std::cout << "Frame summary for conversation " << writer_guid << " >> " << reader_guid << ":" << std::endl;
      std::cout << " - First evidence of writer at frame " << wit->second.first_evidence_frame << " at time " << std::fixed << std::setprecision(3) << wit->second.first_evidence_time << std::endl;
      cframes.insert(wit->second.first_evidence_frame);
      std::cout << " - First evidence of reader at frame " << rit->second.first_evidence_frame << " at time " << std::fixed << std::setprecision(3) << rit->second.first_evidence_time << std::endl;
      cframes.insert(rit->second.first_evidence_frame);
      std::cout << " - First evidence of conversation in frame " << cinfo.first_evidence_frame << " at time " << std::fixed << std::setprecision(3) << cinfo.first_evidence_time << std::endl;
      cframes.insert(cinfo.first_evidence_frame);
      std::map<size_t, std::shared_ptr<info_pair_printer_base>> fmap;
      std::for_each(cinfo.datas.begin(), cinfo.datas.end(), [&](const auto& v) { cframes.insert(v.first->frame_no); fmap[v.first->frame_no].reset(new data_info_pair_printer(v)); });
      std::for_each(cinfo.gaps.begin(), cinfo.gaps.end(), [&](const auto& v) { cframes.insert(v.first->frame_no); fmap[v.first->frame_no].reset(new gap_info_pair_printer(v)); });
      std::for_each(cinfo.heartbeats.begin(), cinfo.heartbeats.end(), [&](const auto& v) { cframes.insert(v.first->frame_no); fmap[v.first->frame_no].reset(new hb_info_pair_printer(v)); });
      std::for_each(cinfo.acknacks.begin(), cinfo.acknacks.end(), [&](const auto& v) { cframes.insert(v.first->frame_no); fmap[v.first->frame_no].reset(new an_info_pair_printer(v)); });
      std::for_each(fmap.begin(), fmap.end(), [&](const auto& v) { v.second->print(std::cout) << std::endl; });
      for (auto fnit = cframes.begin(); fnit != cframes.end(); ++fnit) {
        auto fit = frame_data.find(*fnit);
        if (fit != frame_data.end()) {
          for (auto fdit = fit->second.begin(); fdit != fit->second.end(); ++fdit) {
            std::cout << *fdit << std::endl;
          }
        }
      }
    }
  }

  std::set<std::string> undiscovered_guids;
  std::set<std::string> total_considered_endpoints;
  for (auto it = em.begin(); it != em.end(); ++it) {
    if (domain == 0xFF || domain == it->second.domain_id) {
      total_considered_endpoints.insert(it->second.guid);
      if (conversation_guids.find(it->second.guid) == conversation_guids.end()) {
        if (it->second.reliable) {
          undiscovered_guids.insert(it->second.guid);
        }
      }
    }
  }

  std::cout << "Unique Participant Count: " << participant_guids.size() << std::endl;
  std::cout << "Userdata Endpoint Count: " << userdata_endpoint_guids.size() << std::endl;
  std::cout << "Total Endpoint Count: " << total_considered_endpoints.size() << std::endl;


  if (vm.count("show-undiscovered")) {
    std::cout << "Implicit and/or explicit reliable endpoints without evidence of a conversation:" << std::endl;
    for (auto it = undiscovered_guids.begin(); it != undiscovered_guids.end(); ++it) {
      std::cout << *it << std::endl;
    }
  }

  // Calculate IP Fragmentation Reconstruction Times
  std::multimap<double, const rtps_frame*> ft;
  size_t ft_dropped_count = 0;
  for (auto it = ifm.begin(); it != ifm.end(); ++it) {
    auto it2 = frames.find(it->second.second);
    if (it2 != frames.end()) {
      //std::cout << "frame " << it->second.second << " at " << it2->second.frame_reference_time << " - frame fragment " << it->second.first.first << " at " << it->second.first.second << std::endl;
      ft.insert(decltype(ft)::value_type(it2->second.frame_reference_time - it->second.first.second, &(it2->second)));
    } else {
      ++ft_dropped_count;
    }
  }

  double ft_min = ft.size() ? ft.begin()->first : 0.0;
  double ft_max = ft.size() ? ft.rbegin()->first : 0.0;
  double ft_mean = 0.0, ft_median = 0.0;
  std::vector<double> ft_median_vec;
  for (auto it = ft.begin(); it != ft.end(); ++it) {
    //if (domain == 0xFF || domain == it->second->domain_id) // TODO fix domain lookup for individual frames (domain_id here isn't always correct)
    {
      ft_mean += it->first;
      ft_median_vec.push_back(it->first);
    }
  }
  if (ft_median_vec.size() > 0) {
    ft_mean /= ft_median_vec.size();
    ft_median = ft_median_vec[std::floor((ft_median_vec.size() - 1) / 2)];
  }

  std::cout << "IP Fragmentation Stats (all domains):" << std::endl;
  std::cout << " - Unrecovered fragments: " << ft_dropped_count << std::endl;
  std::cout << " - Individual Reconstruction Times:" << std::endl;
  std::cout << "   - Min:    " << std::setw(8) << std::fixed << std::setprecision(6) << ft_min << std::endl;
  std::cout << "   - Median: " << std::setw(8) << std::fixed << std::setprecision(6) << ft_median << std::endl;
  std::cout << "   - Mean:   " << std::setw(8) << std::fixed << std::setprecision(6) << ft_mean << std::endl;
  std::cout << "   - Max:    " << std::setw(8) << std::fixed << std::setprecision(6) << ft_max << std::flush;
  if (ft.size()) {
    std::cout << " (recovered frame " << ft.rbegin()->second->frame_no << ")" << std::flush;
  }
  std::cout << std::endl;

  // Calculate Discovery Times
  std::multimap<double, const conversation_info*> dt;
  std::multimap<double, const conversation_info*> dt_b;
  std::multimap<double, const conversation_info*> dt_u;
  double last_conversation_time = 0.0;
  for (auto it = cm.begin(); it != cm.end(); ++it) {
    for (auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
      if (domain == 0xFF || domain == it2->second.domain_id) {
        double second_evidence_time = std::max(em[it2->second.writer_guid].first_evidence_time, em[it2->second.reader_guid].first_evidence_time);
        dt.insert(decltype(dt)::value_type(it2->second.first_evidence_time - second_evidence_time, &(it2->second)));
        if (is_guid_builtin(it2->second.writer_guid)) {
          dt_b.insert(decltype(dt)::value_type(it2->second.first_evidence_time - second_evidence_time, &(it2->second)));
        } else {
          dt_u.insert(decltype(dt)::value_type(it2->second.first_evidence_time - second_evidence_time, &(it2->second)));
        }
        if (it2->second.first_evidence_time > last_conversation_time) {
          last_conversation_time = it2->second.first_evidence_time;
        }
      }
    }
  }

  if (vm.count("show-discovery-times")) {
    std::cout << "discovery times:" << std::endl;
  }
  double dt_min = dt.size() ? dt.begin()->first : 0.0;
  double dt_max = dt.size() ? dt.rbegin()->first : 0.0;
  double dt_mean = 0.0, dt_median = 0.0;
  std::vector<double> dt_median_vec;
  for (auto it = dt.begin(); it != dt.end(); ++it) {
    if (domain == 0xFF || domain == it->second->domain_id) {
      dt_mean += it->first;
      dt_median_vec.push_back(it->first);
      if (vm.count("show-discovery-times")) {
        std::cout << it->second->writer_guid << " <-> " << it->second->reader_guid << " took " << it->first << " seconds" << std::endl;
      }
    }
  }
  if (dt_median_vec.size() > 0) {
    dt_mean /= dt_median_vec.size();
    dt_median = dt_median_vec[std::floor((dt_median_vec.size() - 1) / 2)];
  }

  std::cout << "Discovery Stats:" << std::endl;
  std::cout << " - Total Conversations: " << conversation_guids.size() / 2 << std::endl;
  std::cout << " - Reliable endpoints without evidence of conversation: " << undiscovered_guids.size() << std::endl;
  std::cout << " - Individual Discovery Times:" << std::endl;
  std::cout << "   - Min:    " << dt_min << std::endl;
  std::cout << "   - Median: " << dt_median << std::endl;
  std::cout << "   - Mean:   " << dt_mean << std::endl;
  std::cout << "   - Max:    " << dt_max << std::flush;
  if (dt.size()) {
    std::cout << " (" << dt.rbegin()->second->writer_guid << " >> " << dt.rbegin()->second->reader_guid << ")" << std::flush;
  }
  std::cout << std::endl;

  if (vm.count("show-discovery-times")) {
    std::cout << "discovery times:" << std::endl;
  }
  double dt_u_min = dt_u.size() ? dt_u.begin()->first : 0.0;
  double dt_u_max = dt_u.size() ? dt_u.rbegin()->first : 0.0;
  double dt_u_mean = 0.0, dt_u_median = 0.0;
  std::vector<double> dt_u_median_vec;
  for (auto it = dt_u.begin(); it != dt_u.end(); ++it) {
    if (domain == 0xFF || domain == it->second->domain_id) {
      dt_u_mean += it->first;
      dt_u_median_vec.push_back(it->first);
      if (vm.count("show-discovery-times")) {
        std::cout << it->second->writer_guid << " <-> " << it->second->reader_guid << " took " << it->first << " seconds" << std::endl;
      }
    }
  }
  if (dt_u_median_vec.size() > 0) {
    dt_u_mean /= dt_u_median_vec.size();
    dt_u_median = dt_u_median_vec[std::floor((dt_u_median_vec.size() - 1) / 2)];
  }

  std::cout << " - Individual Discovery Times (User Data Endpoints):" << std::endl;
  std::cout << "   - Min:    " << dt_u_min << std::endl;
  std::cout << "   - Median: " << dt_u_median << std::endl;
  std::cout << "   - Mean:   " << dt_u_mean << std::endl;
  std::cout << "   - Max:    " << dt_u_max << std::flush;
  if (dt_u.size()) {
    std::cout << " (" << dt_u.rbegin()->second->writer_guid << " >> " << dt_u.rbegin()->second->reader_guid << ")" << std::flush;
  }
  std::cout << std::endl;

  std::cout << " - Global Discovery Stats:" << std::endl;
  std::cout << "   - Last New Conversation - Last New Participant = " << last_conversation_time - last_participant_time << std::endl;
  std::cout << "   - Last New Conversation - Last New Userdata Endpoint = " << last_conversation_time - last_userdata_endpoint_time << std::endl;

  return 0;
}

