// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef MD5TEST_ISALCPP_H
#define MD5TEST_ISALCPP_H

#include <memory>
#include <cassert>
#include <utility>
#include <future>
#include <array>
#include <queue>
#include <deque>

#include <isa-l_crypto.h>

namespace hash {

class Buffer {
public:
  virtual ~Buffer() {}

  Buffer(const Buffer &o) = delete;

  Buffer(Buffer &&o) = delete;

  virtual uint8_t *data() = 0;

  virtual size_t size() = 0;

protected:
  Buffer() = default;
};

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

  void Update(std::shared_ptr<Buffer> b);

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

  virtual void stream_update(uint32_t id, std::shared_ptr<Buffer> buffer) = 0;

  virtual std::future<std::string> stream_finish(uint32_t id) = 0;

  virtual void stream_release(uint32_t id) = 0;
};

}  // namespace isal
}  // namespace md5
}  // namespace hash

#endif //MD5TEST_ISALCPP_H
