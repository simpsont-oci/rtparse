#include "tshark_parsing.hpp"

#include <ios>
#include <iostream>
#include <sstream>

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

void process_frame(const string_vec& tshark_frame_data, std::map<size_t, rtps_frame>& frames, ip_frag_map& ifm) {

  string_vec frame_header;
  string_vec eth_header;
  string_vec ip_header;
  string_vec udp_header;
  string_vec rtps_header;
  std::vector<string_vec> rtps_submessages;

  for (auto it = tshark_frame_data.begin(); it != tshark_frame_data.end(); ++it) {
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

void process_frame_data(const tshark_frame_map& fd, std::map<size_t, rtps_frame>& frames, ip_frag_map& ifm) {
  for (auto it = fd.begin(); it != fd.end(); ++it) {
    process_frame(it->second, frames, ifm);
  }
}

