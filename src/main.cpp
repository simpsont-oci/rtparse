#include "boost/program_options/parsers.hpp"
#include "boost/program_options/variables_map.hpp"

#include "conversation_info.hpp"
#include "endpoint_info.hpp"
#include "frames.hpp"
#include "info_pairs.hpp"
#include "net_info.hpp"
#include "tshark_parsing.hpp"
#include "utils.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>

namespace po = boost::program_options;

int run(const po::variables_map& vm);

int main(int argc, char** argv)
{
  int result = 0;
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

  if (vm.count("help") != 0u) {
    std::cout << desc << "\n";
    return 1;
  }

  try {
    result = run(vm);
  } catch (...) {
    result = 1;
  }

  return result;
}

int run(const po::variables_map& vm) { 

  std::string filename;
  if (vm.count("file") != 0u) {
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
  if (vm.count("domain") != 0u) {
    domain = vm["domain"].as<uint16_t>();
  }

  /*
  // TODO Add support for filtering by guid eventually?
  string_vec guids;
  if (vm.count("guid") != 0u) {
    guids = vm["guid"].as<string_vec>();
    for (auto it = guids.begin(); it != guids.end(); ++it) {
      std::cout << "tracking guid: " << *it << std::endl;
    }
  }
  */

  tshark_frame_map tfm;

  std::string line;
  std::getline(ifs, line);
  size_t frame_no = 0;
  while (ifs.good()) {
    if (line.substr(0, 6) == "Frame ") {
      std::stringstream ss(line.substr(6, line.find(':')));
      ss >> frame_no;
      //std::cout << "Found header for frame " << frame << std::endl;
    }
    tfm[frame_no].push_back(line);
    std::getline(ifs, line);
  }

  rtps_frame_map frames;
  ip_frag_map ifm;
  process_frame_data(tfm, frames, ifm);

  endpoint_map em;
  gather_participant_info(frames, em);
  gather_endpoint_info(frames, em);

  // Display Endpoint Info
  if (vm.count("show-endpoints") != 0u) {
    std::cout << "Endpoint Info:" << std::endl;
    for (auto & it : em) {
      if (domain == 0xFF || domain == it.second.domain_id) {
        std::cout << it.second << std::endl;
      }
    }
  }

  std::set<std::string> participant_guids;
  std::set<std::string> userdata_endpoint_guids;
  double last_participant_time = 0.0;
  double last_userdata_endpoint_time = 0.0;
  for (auto & frame : frames) {
    if (!frame.second.data_vec.empty()) {
      if (domain == 0xFF || domain == frame.second.domain_id) {
        if (!frame.second.data_vec.front().participant_guid.empty()) {
          if (participant_guids.insert(frame.second.data_vec.front().participant_guid).second) {
            last_participant_time = frame.second.frame_reference_time;
          }
        }
        if (!frame.second.data_vec.front().endpoint_guid.empty()) {
          if (userdata_endpoint_guids.insert(frame.second.data_vec.front().endpoint_guid).second) {
            last_userdata_endpoint_time = frame.second.frame_reference_time;
          }
        }
      }
    }
  }

  if (vm.count("show-participants") != 0u) {
    std::cout << "Participant guids:" << std::endl;
    for (const auto & participant_guid : participant_guids) {
      std::cout << participant_guid << std::endl;
    }
  }

  conversation_map cm;
  gather_conversation_info(frames, em, cm);

  std::set<std::string> conversation_guids;
  if (vm.count("show-conversations") != 0u) {
    std::cout << "Conversations Info:" << std::endl;
  }
  for (auto & it : cm) {
    for (auto & it2 : it.second) {
      if (domain == 0xFF || domain == it2.second.domain_id) {
        conversation_guids.insert(it2.second.writer_guid);
        conversation_guids.insert(it2.second.reader_guid);
        if (vm.count("show-conversations") != 0u) {
          std::cout << "Conversation found: " << it2.second.writer_guid << " >> " << it2.second.reader_guid << " @ " << it2.second.first_evidence_time << std::endl;
        }
      }
    }
  }

  if (vm.count("show-conversation-frames") != 0u) {
    string_vec clist = vm["show-conversation-frames"].as<string_vec>();
    for (auto & it : clist) {
      size_t cpos = 0;
      if (it.length() != 65 || ((cpos = it.find(',')) != 32)) {
        std::cout << "error parsing conversation! cpos = " << cpos << std::endl;
        continue;
      }
      std::string guid1 = it.substr(0, 32);
      std::string guid2 = it.substr(33, 32);
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
      for (size_t cframe : cframes) {
        auto fit = tfm.find(cframe);
        if (fit != tfm.end()) {
          for (auto & tfmit : fit->second) {
            std::cout << tfmit << std::endl;
          }
        }
      }
    }
  }

  std::set<std::string> undiscovered_guids;
  std::set<std::string> total_considered_endpoints;
  for (auto & it : em) {
    if (domain == 0xFF || domain == it.second.domain_id) {
      total_considered_endpoints.insert(it.second.guid);
      if (conversation_guids.find(it.second.guid) == conversation_guids.end()) {
        if (it.second.reliable) {
          undiscovered_guids.insert(it.second.guid);
        }
      }
    }
  }

  std::cout << "Unique Participant Count: " << participant_guids.size() << std::endl;
  std::cout << "Userdata Endpoint Count: " << userdata_endpoint_guids.size() << std::endl;
  std::cout << "Total Endpoint Count: " << total_considered_endpoints.size() << std::endl;


  if (vm.count("show-undiscovered") != 0u) {
    std::cout << "Implicit and/or explicit reliable endpoints without evidence of a conversation:" << std::endl;
    for (const auto & undiscovered_guid : undiscovered_guids) {
      std::cout << undiscovered_guid << std::endl;
    }
  }

  // Calculate IP Fragmentation Reconstruction Times
  std::multimap<double, const rtps_frame*> ft;
  size_t ft_dropped_count = 0;
  for (auto & it : ifm) {
    auto it2 = frames.find(it.second.second);
    if (it2 != frames.end()) {
      //std::cout << "frame " << it->second.second << " at " << it2->second.frame_reference_time << " - frame fragment " << it->second.first.first << " at " << it->second.first.second << std::endl;
      ft.insert(decltype(ft)::value_type(it2->second.frame_reference_time - it.second.first.second, &(it2->second)));
    } else {
      ++ft_dropped_count;
    }
  }

  double ft_min = ft.empty() ? 0.0 : ft.begin()->first;
  double ft_max = ft.empty() ? 0.0 : ft.rbegin()->first;
  double ft_mean = 0.0, ft_median = 0.0;
  std::vector<double> ft_median_vec;
  for (auto & it : ft) {
    //if (domain == 0xFF || domain == it->second->domain_id) // TODO fix domain lookup for individual frames (domain_id here isn't always correct)
    {
      ft_mean += it.first;
      ft_median_vec.push_back(it.first);
    }
  }
  if (!ft_median_vec.empty()) {
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
  if (!ft.empty()) {
    std::cout << " (recovered frame " << ft.rbegin()->second->frame_no << ")" << std::flush;
  }
  std::cout << std::endl;

  // Calculate Discovery Times
  std::multimap<double, const conversation_info*> dt;
  std::multimap<double, const conversation_info*> dt_b;
  std::multimap<double, const conversation_info*> dt_u;
  double last_conversation_time = 0.0;
  for (auto & it : cm) {
    for (auto & it2 : it.second) {
      if (domain == 0xFF || domain == it2.second.domain_id) {
        double second_evidence_time = std::max(em[it2.second.writer_guid].first_evidence_time, em[it2.second.reader_guid].first_evidence_time);
        dt.insert(decltype(dt)::value_type(it2.second.first_evidence_time - second_evidence_time, &(it2.second)));
        if (is_guid_builtin(it2.second.writer_guid)) {
          dt_b.insert(decltype(dt)::value_type(it2.second.first_evidence_time - second_evidence_time, &(it2.second)));
        } else {
          dt_u.insert(decltype(dt)::value_type(it2.second.first_evidence_time - second_evidence_time, &(it2.second)));
        }
        if (it2.second.first_evidence_time > last_conversation_time) {
          last_conversation_time = it2.second.first_evidence_time;
        }
      }
    }
  }

  if (vm.count("show-discovery-times") != 0u) {
    std::cout << "discovery times:" << std::endl;
  }
  double dt_min = dt.empty() ? 0.0 : dt.begin()->first;
  double dt_max = dt.empty() ? 0.0 : dt.rbegin()->first;
  double dt_mean = 0.0, dt_median = 0.0;
  std::vector<double> dt_median_vec;
  for (auto & it : dt) {
    if (domain == 0xFF || domain == it.second->domain_id) {
      dt_mean += it.first;
      dt_median_vec.push_back(it.first);
      if (vm.count("show-discovery-times") != 0u) {
        std::cout << it.second->writer_guid << " <-> " << it.second->reader_guid << " took " << it.first << " seconds" << std::endl;
      }
    }
  }
  if (!dt_median_vec.empty()) {
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
  if (!dt.empty()) {
    std::cout << " (" << dt.rbegin()->second->writer_guid << " >> " << dt.rbegin()->second->reader_guid << ")" << std::flush;
  }
  std::cout << std::endl;

  if (vm.count("show-discovery-times") != 0u) {
    std::cout << "discovery times:" << std::endl;
  }
  double dt_u_min = dt_u.empty() ? 0.0 : dt_u.begin()->first;
  double dt_u_max = dt_u.empty() ? 0.0 : dt_u.rbegin()->first;
  double dt_u_mean = 0.0, dt_u_median = 0.0;
  std::vector<double> dt_u_median_vec;
  for (auto & it : dt_u) {
    if (domain == 0xFF || domain == it.second->domain_id) {
      dt_u_mean += it.first;
      dt_u_median_vec.push_back(it.first);
      if (vm.count("show-discovery-times") != 0u) {
        std::cout << it.second->writer_guid << " <-> " << it.second->reader_guid << " took " << it.first << " seconds" << std::endl;
      }
    }
  }
  if (!dt_u_median_vec.empty()) {
    dt_u_mean /= dt_u_median_vec.size();
    dt_u_median = dt_u_median_vec[std::floor((dt_u_median_vec.size() - 1) / 2)];
  }

  std::cout << " - Individual Discovery Times (User Data Endpoints):" << std::endl;
  std::cout << "   - Min:    " << dt_u_min << std::endl;
  std::cout << "   - Median: " << dt_u_median << std::endl;
  std::cout << "   - Mean:   " << dt_u_mean << std::endl;
  std::cout << "   - Max:    " << dt_u_max << std::flush;
  if (!dt_u.empty()) {
    std::cout << " (" << dt_u.rbegin()->second->writer_guid << " >> " << dt_u.rbegin()->second->reader_guid << ")" << std::flush;
  }
  std::cout << std::endl;

  std::cout << " - Global Discovery Stats:" << std::endl;
  std::cout << "   - Last New Conversation - Last New Participant = " << last_conversation_time - last_participant_time << std::endl;
  std::cout << "   - Last New Conversation - Last New Userdata Endpoint = " << last_conversation_time - last_userdata_endpoint_time << std::endl;

  return 0;
}

