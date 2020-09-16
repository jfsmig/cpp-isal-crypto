// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef HASH_ISAL_MD5_HPP_
#define HASH_ISAL_MD5_HPP_

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

class Stream;

/**
 * MD5 Scheduler for multiple streams.
 */
class Scheduler {
 public:
  /**
   * Instantiate a Scheduler implementation.
   * The technique helps hiding the implementation details and prevents
   * too many headers to be included.
   *
   * @return A shared_pointer to a valid Scheduler implementation.
   */
  static std::shared_ptr<Scheduler> New();

  virtual ~Scheduler() {}

  /**
   * Synchronous computation.
   *
   * @param s
   * @return
   */
  std::string Compute(StringPtr s);

  virtual std::unique_ptr<Stream> MakeStream() = 0;

  /**
   *
   * @param id
   * @param b
   */
  virtual void UpdateStream(uint32_t id, StringPtr b) = 0;

  /**
   *
   * @param id
   * @return
   */
  virtual std::shared_future<std::string> FinishStream(uint32_t id) = 0;

  /**
   *
   * @param id
   */
  virtual void ReleaseStream(uint32_t id) = 0;

 protected:
  Scheduler() {}

  Scheduler(const Scheduler &o) = delete;

  Scheduler(Scheduler &&o) = delete;
};

/**
 * RAII of a single checksum computation.
 *
 */
class Stream {
 public:
  Stream() = delete;

  Stream(const Stream &o) = delete;

  Stream(Stream &&o) :
      scheduler_(std::move(o.scheduler_)), index_{o.index_} {}

  explicit Stream(std::shared_ptr<Scheduler> srv, uint32_t index) :
      scheduler_(std::move(srv)), index_{index} {}

  ~Stream() {
    scheduler_->ReleaseStream(index_);
  }

  Stream& Update(StringPtr b) {
    scheduler_->UpdateStream(index_, std::move(b));
    return *this;
  }

  std::shared_future<std::string> Finish() {
    return scheduler_->FinishStream(index_);
  }

 private:
  std::shared_ptr<Scheduler> scheduler_;
  uint32_t index_;
};

}  // namespace isal
}  // namespace md5
}  // namespace hash

#endif  // HASH_ISAL_MD5_HPP_
