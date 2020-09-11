// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef HASH_ISAL_MD5_HPP_
#define HASH_ISAL_MD5_HPP_

#include <isa-l_crypto.h>

#include <memory>
#include <cassert>
#include <utility>
#include <future>  // NOLINT
#include <array>
#include <queue>
#include <string>

namespace hash {

using StringPtr = std::shared_ptr<std::string>;

namespace md5 {
namespace isal {

class SchedulerInterface;

/**
 * Represents the hash computation of a single stream.
 */
class Stream {
  friend class SchedulerInterface;

 public:
  Stream() = delete;

  Stream(Stream &&o) = delete;

  Stream(const Stream &o) = delete;

  ~Stream();

  void Update(StringPtr b);

  std::future<std::string> Finish();

  explicit Stream(SchedulerInterface *srv, uint32_t index) :
      scheduler_{srv}, index_{index} {}

 private:
  SchedulerInterface *scheduler_;
  uint32_t index_;
};

/**
 * MD5 Scheduler for multiple streams.
 */
class SchedulerInterface {
  friend class Stream;

 public:
  virtual ~SchedulerInterface() {}

  virtual std::shared_ptr<Stream> MakeStream() = 0;

  static std::shared_ptr<SchedulerInterface> New();

 protected:
  SchedulerInterface() {}

  SchedulerInterface(const SchedulerInterface &o) = delete;

  SchedulerInterface(SchedulerInterface &&o) = delete;

  virtual void stream_update(uint32_t id, StringPtr b) = 0;

  virtual std::future<std::string> stream_finish(uint32_t id) = 0;

  // Must no throw an exception upon a non-critical error since the function is used
  // in destructors of RAII Stream objects
  virtual void stream_release(uint32_t id) noexcept = 0;
};

}  // namespace isal
}  // namespace md5
}  // namespace hash

#endif  // HASH_ISAL_MD5_HPP_
