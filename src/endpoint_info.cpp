#include "endpoint_info.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

std::ostream& operator<<(std::ostream& os, const endpoint_info& info) {
  return os << "( " << info.guid << ", " << info.src_net << ", " << info.dst_net_map << ", " << info.domain_id << ", " << info.first_evidence_frame << ", " << std::fixed << std::setprecision(3) << info.first_evidence_time << " )" << std::flush;
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
  } 
    em[info.guid] = info;
    return true;
  
}

void gather_participant_info(const std::map<size_t, rtps_frame>& frames, endpoint_map& em) {
  for (const auto & frame : frames) {
    for (auto dit = frame.second.data_vec.begin(); dit != frame.second.data_vec.end(); ++dit) {
      if (dit->writer_id == "000100c2") {
        endpoint_info info;
        info.src_net = { frame.second.src_mac, frame.second.src_ip, frame.second.src_port };
        info.first_evidence_frame = frame.second.frame_no;
        info.first_evidence_time = frame.second.frame_reference_time;
        info.reliable = false;
        info.guid = frame.second.guid_prefix + dit->writer_id;

        if (info.domain_id == 0) {
          uint16_t port = 0;
          std::stringstream ss(frame.second.dst_port);
          ss >> port;
          info.domain_id = (port < 7400 ? 0xFF : static_cast<uint16_t>(port - 7400) / 250);
        }

        create_or_merge_endpoint_info(info, em);
      }
    }
  }
}

void gather_endpoint_info(const std::map<size_t, rtps_frame>& frames, endpoint_map& em) {
  for (const auto & frame : frames) {
    endpoint_info info;
    info.src_net = { frame.second.src_mac, frame.second.src_ip, frame.second.src_port };
    auto pit = em.find(frame.second.guid_prefix + "000100c2");
    if (pit != em.end()) {
      info.domain_id = pit->second.domain_id;
    }
    info.first_evidence_frame = frame.second.frame_no;
    info.first_evidence_time = frame.second.frame_reference_time;

    for (auto dit = frame.second.data_vec.begin(); dit != frame.second.data_vec.end(); ++dit) {
      endpoint_info dataw_info(info);
      dataw_info.guid = frame.second.guid_prefix + dit->writer_id;
      if (!dit->participant_guid.empty()) {
        endpoint_info spdp_info;
        for (size_t i = 0; i < dit->metatraffic_unicast_locator_ips.size(); ++i) {
          create_or_merge_net_info(net_info("", dit->metatraffic_unicast_locator_ips[i], dit->metatraffic_unicast_locator_ports[i]), spdp_info.dst_net_map);
        }
        for (size_t i = 0; i < dit->metatraffic_multicast_locator_ips.size(); ++i) {
          create_or_merge_net_info(net_info("", dit->metatraffic_multicast_locator_ips[i], dit->metatraffic_multicast_locator_ports[i]), spdp_info.dst_net_map);
        }
        spdp_info.first_evidence_frame = dataw_info.first_evidence_frame;
        spdp_info.first_evidence_time = dataw_info.first_evidence_time;
        spdp_info.spdp_announcements.emplace_back(data_info_pair(&(frame.second), &(*dit)));

        if ((dit->builtins & (0x00000001u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + "000100c2"; // Participant Writer
          spdp_info.reliable = false;
          create_or_merge_endpoint_info(spdp_info, em);
        }

        if ((dit->builtins & (0x00000001u << 1u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + "000100c7"; // Participant Reader
          spdp_info.reliable = false;
          create_or_merge_endpoint_info(spdp_info, em);
        }

        if ((dit->builtins & (0x00000001u << 2u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + "000003c2"; // Publications Writer
          spdp_info.reliable = true;
          create_or_merge_endpoint_info(spdp_info, em);
        }

        if ((dit->builtins & (0x00000001u << 3u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + "000003c7"; // Publications Reader
          spdp_info.reliable = true;
          create_or_merge_endpoint_info(spdp_info, em);
        }

        if ((dit->builtins & (0x00000001u << 4u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + "000004c2"; // Subscriptions Writer
          spdp_info.reliable = true;
          create_or_merge_endpoint_info(spdp_info, em);
        }

        if ((dit->builtins & (0x00000001u << 5u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + "000004c7"; // Subscriptions Reader
          spdp_info.reliable = true;
          create_or_merge_endpoint_info(spdp_info, em);
        }

        if ((dit->builtins & (0x00000001u << 6u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + ""; // Participant Proxy Writer
          spdp_info.reliable = true;
          //create_or_merge_endpoint_info(spdp_info, em); // If we don't have an entity ID for this (from the spec), we can't add it
        }

        if ((dit->builtins & (0x00000001u << 7u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + ""; // Participant Proxy Reader
          spdp_info.reliable = true;
          //create_or_merge_endpoint_info(spdp_info, em); // If we don't have an entity ID for this (from the spec), we can't add it
        }

        if ((dit->builtins & (0x00000001u << 8u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + ""; // Participant State Writer
          spdp_info.reliable = true;
          //create_or_merge_endpoint_info(spdp_info, em); // If we don't have an entity ID for this (from the spec), we can't add it
        }

        if ((dit->builtins & (0x00000001u << 9u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + ""; // Participant State Reader
          spdp_info.reliable = true;
          //create_or_merge_endpoint_info(spdp_info, em); // If we don't have an entity ID for this (from the spec), we can't add it
        }

        if ((dit->builtins & (0x00000001u << 10u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + "000200c2"; // Participant Message Writer
          spdp_info.reliable = true;
          create_or_merge_endpoint_info(spdp_info, em);
        }

        if ((dit->builtins & (0x00000001u << 11u)) != 0u) {
          spdp_info.guid = dit->participant_guid.substr(0, 24) + "000200c7"; // Participant Message Reader
          spdp_info.reliable = true;
          create_or_merge_endpoint_info(spdp_info, em);
        }
      }
      if (!dit->endpoint_guid.empty()) {
        endpoint_info sedp_info;
        sedp_info.guid = dit->endpoint_guid;
        for (size_t i = 0; i < dit->unicast_locator_ips.size(); ++i) {
          create_or_merge_net_info(net_info("", dit->unicast_locator_ips[i], dit->unicast_locator_ports[i]), sedp_info.dst_net_map);
        }
        for (size_t i = 0; i < dit->multicast_locator_ips.size(); ++i) {
          create_or_merge_net_info(net_info("", dit->multicast_locator_ips[i], dit->multicast_locator_ports[i]), sedp_info.dst_net_map);
        }
        sedp_info.domain_id = dataw_info.domain_id;
        sedp_info.first_evidence_frame = dataw_info.first_evidence_frame;
        sedp_info.first_evidence_time = dataw_info.first_evidence_time;
        sedp_info.sedp_announcements.emplace_back(data_info_pair(&(frame.second), &(*dit)));
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
            rw_info.sedp_announcements.emplace_back(data_info_pair(&(frame.second), &(*dit)));
            create_or_merge_endpoint_info(rw_info, em);
          }
        }
      }
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(frame.second, dit->sm_order)) != frame.second.info_dst_vec.end() && dit->reader_id != "00000000") {
        endpoint_info datar_info;
        datar_info.guid = idit->guid_prefix + dit->reader_id;
        create_or_merge_net_info(net_info(frame.second.dst_mac, frame.second.dst_ip, frame.second.dst_port), datar_info.dst_net_map);
        datar_info.domain_id = dataw_info.domain_id;
        datar_info.first_evidence_frame = dataw_info.first_evidence_frame;
        datar_info.first_evidence_time = dataw_info.first_evidence_time;
        create_or_merge_endpoint_info(datar_info, em);
      } else {
        dataw_info.datas.emplace_back(data_info_pair(&(frame.second), &(*dit)));
      }
      create_or_merge_endpoint_info(dataw_info, em);
    }
    for (auto git = frame.second.gap_vec.begin(); git != frame.second.gap_vec.end(); ++git) {
      endpoint_info gapw_info(info);
      gapw_info.guid = frame.second.guid_prefix + git->writer_id;
      //gapw_info.reliable = true; // TODO Is this correct?
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(frame.second, git->sm_order)) != frame.second.info_dst_vec.end() && git->reader_id != "00000000") {
        endpoint_info gapr_info;
        gapr_info.guid = idit->guid_prefix + git->reader_id;
        if (frame.second.info_dst_vec.size() == 1) {
          // We do this to handle the weird durabile writer gap split & resend-to-all-locators issue which sometimes gives us gaps with wrong ip/udp dst info
          create_or_merge_net_info(net_info(frame.second.dst_mac, frame.second.dst_ip, frame.second.dst_port), gapr_info.dst_net_map);
        }
        gapr_info.domain_id = gapw_info.domain_id;
        gapr_info.first_evidence_frame = gapw_info.first_evidence_frame;
        gapr_info.first_evidence_time = gapw_info.first_evidence_time;
        //gapr_info.reliable = true; // TODO Is this correct?
        create_or_merge_endpoint_info(gapr_info, em);
      } else {
        gapw_info.gaps.emplace_back(gap_info_pair(&(frame.second), &(*git)));
      }
      create_or_merge_endpoint_info(gapw_info, em);
    }
    for (auto hit = frame.second.heartbeat_vec.begin(); hit != frame.second.heartbeat_vec.end(); ++hit) {
      endpoint_info hbw_info(info);
      hbw_info.guid = frame.second.guid_prefix + hit->writer_id;
      //hbw_info.reliable = true; // TODO Is this correct?
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(frame.second, hit->sm_order)) != frame.second.info_dst_vec.end() && hit->reader_id != "00000000") {
        endpoint_info hbr_info;
        hbr_info.guid = idit->guid_prefix + hit->reader_id;
        create_or_merge_net_info(net_info(frame.second.dst_mac, frame.second.dst_ip, frame.second.dst_port), hbr_info.dst_net_map);
        hbr_info.domain_id = hbw_info.domain_id;
        hbr_info.first_evidence_frame = hbw_info.first_evidence_frame;
        hbr_info.first_evidence_time = hbw_info.first_evidence_time;
        //hbr_info.reliable = true; // TODO Is this correct?
        create_or_merge_endpoint_info(hbr_info, em);
      } else {
        hbw_info.heartbeats.emplace_back(hb_info_pair(&(frame.second), &(*hit)));
      }
      create_or_merge_endpoint_info(hbw_info, em);
    }
    for (auto ait = frame.second.acknack_vec.begin(); ait != frame.second.acknack_vec.end(); ++ait) {
      endpoint_info anr_info(info);
      anr_info.guid = frame.second.guid_prefix + ait->reader_id; // acknack comes from reader side
      anr_info.reliable = true;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(frame.second, ait->sm_order)) != frame.second.info_dst_vec.end() && ait->writer_id != "00000000") {
        endpoint_info anw_info;
        anw_info.guid = idit->guid_prefix + ait->writer_id; // but also tells us about writer side
        create_or_merge_net_info(net_info(frame.second.dst_mac, frame.second.dst_ip, frame.second.dst_port), anw_info.dst_net_map);
        anw_info.domain_id = anr_info.domain_id;
        anw_info.first_evidence_frame = anr_info.first_evidence_frame;
        anw_info.first_evidence_time = anr_info.first_evidence_time;
        anw_info.reliable = true;
        create_or_merge_endpoint_info(anw_info, em);
      } else {
        anr_info.acknacks.emplace_back(an_info_pair(&(frame.second), &(*ait)));
      }
      create_or_merge_endpoint_info(anr_info, em);
    }
  }
}

