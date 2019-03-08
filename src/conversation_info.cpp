#include "conversation_info.hpp"

#include "filtering.hpp"

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
  for (const auto & frame : frames) {
    conversation_info info;
    info.domain_id = frame.second.domain_id;
    info.first_evidence_frame = frame.second.frame_no;
    info.first_evidence_time = frame.second.frame_reference_time;
    for (auto dit = frame.second.data_vec.begin(); dit != frame.second.data_vec.end(); ++dit) {
      info.writer_guid = frame.second.guid_prefix + dit->writer_id;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(frame.second, dit->sm_order)) != frame.second.info_dst_vec.end()) {
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
            info.datas.emplace_back(data_info_pair(&(frame.second), &(*dit)));
            cm[info.writer_guid][info.reader_guid] = info;
          } else {
            auto rcit = wcit->second.find(info.reader_guid);
            if (rcit == wcit->second.end()) {
              copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
              info.datas.emplace_back(data_info_pair(&(frame.second), &(*dit)));
              wcit->second[info.reader_guid] = info;
            } else {
              rcit->second.datas.emplace_back(data_info_pair(&(frame.second), &(*dit)));
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
    for (auto git = frame.second.gap_vec.begin(); git != frame.second.gap_vec.end(); ++git) {
      info.writer_guid = frame.second.guid_prefix + git->writer_id;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(frame.second, git->sm_order)) != frame.second.info_dst_vec.end()) {
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
            info.gaps.emplace_back(gap_info_pair(&(frame.second), &(*git)));
            cm[info.writer_guid][info.reader_guid] = info;
          } else {
            auto rcit = wcit->second.find(info.reader_guid);
            if (rcit == wcit->second.end()) {
              copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
              info.gaps.emplace_back(gap_info_pair(&(frame.second), &(*git)));
              wcit->second[info.reader_guid] = info;
            } else {
              rcit->second.gaps.emplace_back(gap_info_pair(&(frame.second), &(*git)));
            }
          }
        }
      }
    }
    for (auto hit = frame.second.heartbeat_vec.begin(); hit != frame.second.heartbeat_vec.end(); ++hit) {
      info.writer_guid = frame.second.guid_prefix + hit->writer_id;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(frame.second, hit->sm_order)) != frame.second.info_dst_vec.end()) {
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
            info.heartbeats.emplace_back(hb_info_pair(&(frame.second), &(*hit)));
            cm[info.writer_guid][info.reader_guid] = info;
          } else {
            auto rcit = wcit->second.find(info.reader_guid);
            if (rcit == wcit->second.end()) {
              copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
              info.heartbeats.emplace_back(hb_info_pair(&(frame.second), &(*hit)));
              wcit->second[info.reader_guid] = info;
            } else {
              rcit->second.heartbeats.emplace_back(hb_info_pair(&(frame.second), &(*hit)));
            }
          }
        }
      }
    }
    for (auto ait = frame.second.acknack_vec.begin(); ait != frame.second.acknack_vec.end(); ++ait) {
      info.reader_guid = frame.second.guid_prefix + ait->reader_id;
      std::vector<rtps_info_dst>::const_iterator idit;
      if ((idit = find_previous_dst(frame.second, ait->sm_order)) != frame.second.info_dst_vec.end()) {
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
            info.acknacks.emplace_back(an_info_pair(&(frame.second), &(*ait)));
            cm[info.writer_guid][info.reader_guid] = info;
          } else {
            auto rcit = wcit->second.find(info.reader_guid);
            if (rcit == wcit->second.end()) {
              copy_endpoint_details_relevant_to_conversation(weit->second, reit->second, em, info);
              info.acknacks.emplace_back(an_info_pair(&(frame.second), &(*ait)));
              wcit->second[info.reader_guid] = info;
            } else {
              rcit->second.acknacks.emplace_back(an_info_pair(&(frame.second), &(*ait)));
            }
          }
        }
      }
    }
  }
}

