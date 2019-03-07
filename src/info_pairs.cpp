#include "info_pairs.hpp"

#include <iomanip>

info_pair_printer_base::info_pair_printer_base() {}

data_info_pair_printer::data_info_pair_printer(const data_info_pair& p) : pair(p) {}

std::ostream& data_info_pair_printer::print(std::ostream& os) const {
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

gap_info_pair_printer::gap_info_pair_printer(const gap_info_pair& p) : pair(p) {}

std::ostream& gap_info_pair_printer::print(std::ostream& os) const {
  const auto& frame = *(pair.first);
  const auto& gap = *(pair.second);
  auto idit = find_previous_dst(frame, gap.sm_order);
  std::string display_guid = (idit == frame.info_dst_vec.end() ? std::string("????????????????????????") : idit->guid_prefix) + gap.reader_id;
  std::string flagstr = std::string("---") + (gap.flags & 0x01 ? "E" : "-");
  return os << " - Gap in frame       " << std::setw(6) << frame.frame_no << " at time " << std::setw(7) << std::fixed << std::setprecision(3) << frame.frame_reference_time
    << " sent to " << display_guid << " @ " << frame.dst_ip << ":" << frame.dst_port
    << " :: flags = " << flagstr << ", start = " << gap.gap_start << ", base = " << gap.bitmap_base << ", bitmap = " << gap.bitmap  << std::flush;
}

hb_info_pair_printer::hb_info_pair_printer(const hb_info_pair& p) : pair(p) {}

std::ostream& hb_info_pair_printer::print(std::ostream& os) const {
  const auto& frame = *(pair.first);
  const auto& heartbeat = *(pair.second);
  auto idit = find_previous_dst(frame, heartbeat.sm_order);
  std::string display_guid = (idit == frame.info_dst_vec.end() ? std::string("????????????????????????") : idit->guid_prefix) + heartbeat.reader_id;
  std::string flagstr = std::string("-") + (heartbeat.flags & 0x04 ? "L" : "-") + (heartbeat.flags & 0x02 ? "F" : "-") + (heartbeat.flags & 0x01 ? "E" : "-");
  return os << " - Heartbeat in frame " << std::setw(6) << frame.frame_no << " at time " << std::setw(7) << std::fixed << std::setprecision(3) << frame.frame_reference_time
    << " sent to " << display_guid << " @ " << frame.dst_ip << ":" << frame.dst_port
    << " :: flags = " << flagstr << ", first = " << heartbeat.first_seq_num << ", last = " << heartbeat.last_seq_num << std::flush;
}

an_info_pair_printer::an_info_pair_printer(const an_info_pair& p) : pair(p) {}

std::ostream& an_info_pair_printer::print(std::ostream& os) const {
  const auto& frame = *(pair.first);
  const auto& acknack = *(pair.second);
  auto idit = find_previous_dst(frame, acknack.sm_order);
  std::string display_guid = (idit == frame.info_dst_vec.end() ? std::string("????????????????????????") : idit->guid_prefix) + acknack.writer_id;
  std::string flagstr = std::string("--") + (acknack.flags & 0x02 ? "F" : "-") + (acknack.flags & 0x01 ? "E" : "-");
  return os << " - Acknack in frame   " << std::setw(6) << frame.frame_no << " at time " << std::setw(7) << std::fixed << std::setprecision(3) << frame.frame_reference_time
    << " sent to " << display_guid << " @ " << frame.dst_ip << ":" << frame.dst_port
    << " :: flags = " << flagstr << ", base = " << acknack.bitmap_base << ", bitmap = " << acknack.bitmap  << std::flush;
}

