#pragma once

#include "frames.hpp"

#include <iostream>
#include <utility>

using data_info_pair = std::pair<const rtps_frame*, const rtps_data*>;
using gap_info_pair = std::pair<const rtps_frame*, const rtps_gap*>;
using hb_info_pair = std::pair<const rtps_frame*, const rtps_heartbeat*>;
using an_info_pair = std::pair<const rtps_frame*, const rtps_acknack*>;

struct info_pair_printer_base {
  info_pair_printer_base() = default;
  info_pair_printer_base(const info_pair_printer_base&) = default;
  info_pair_printer_base(info_pair_printer_base&&) = default;
  virtual ~info_pair_printer_base() = default;
  info_pair_printer_base& operator=(const info_pair_printer_base&) = default;
  info_pair_printer_base& operator=(info_pair_printer_base&&) = default;
  virtual std::ostream& print(std::ostream& os) const = 0;
};

struct data_info_pair_printer : public info_pair_printer_base {
  explicit data_info_pair_printer(const data_info_pair& p);
  const data_info_pair& pair;
  std::ostream& print(std::ostream& os) const override;
};

struct gap_info_pair_printer : public info_pair_printer_base {
  explicit gap_info_pair_printer(const gap_info_pair& p);
  const gap_info_pair& pair;
  std::ostream& print(std::ostream& os) const override;
};

struct hb_info_pair_printer : public info_pair_printer_base {
  explicit hb_info_pair_printer(const hb_info_pair& p);
  const hb_info_pair& pair;
  std::ostream& print(std::ostream& os) const override;
};

struct an_info_pair_printer : public info_pair_printer_base {
  explicit an_info_pair_printer(const an_info_pair& p);
  const an_info_pair& pair;
  std::ostream& print(std::ostream& os) const override;
};


