#pragma once

#include "frames.hpp"

#include <utility>
#include <iostream>

typedef std::pair<const rtps_frame*, const rtps_data*> data_info_pair;
typedef std::pair<const rtps_frame*, const rtps_gap*> gap_info_pair;
typedef std::pair<const rtps_frame*, const rtps_heartbeat*> hb_info_pair;
typedef std::pair<const rtps_frame*, const rtps_acknack*> an_info_pair;

struct info_pair_printer_base {
  virtual ~info_pair_printer_base() {}
  virtual std::ostream& print(std::ostream& os) const = 0;
protected:
  info_pair_printer_base();
};

struct data_info_pair_printer : public info_pair_printer_base {
  data_info_pair_printer(const data_info_pair& p);
  const data_info_pair& pair;
  std::ostream& print(std::ostream& os) const;
};

struct gap_info_pair_printer : public info_pair_printer_base {
  gap_info_pair_printer(const gap_info_pair& p);
  const gap_info_pair& pair;
  std::ostream& print(std::ostream& os) const;
};

struct hb_info_pair_printer : public info_pair_printer_base {
  hb_info_pair_printer(const hb_info_pair& p);
  const hb_info_pair& pair;
  std::ostream& print(std::ostream& os) const;
};

struct an_info_pair_printer : public info_pair_printer_base {
  an_info_pair_printer(const an_info_pair& p);
  const an_info_pair& pair;
  std::ostream& print(std::ostream& os) const;
};


