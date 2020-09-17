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
using Digest = std::shared_future<std::string>;

namespace md5 {
namespace isal {

class Hash;

/**
 * MD5 Scheduler for multiple streams.
 */
class Scheduler {
 public:
  /**
   * Instantiate a Scheduler implementation.
   * The purpose of the technique helps hiding the implementation details
   * of th Scheduler and prevents too specific or too many headers to be
   * required by the calling app.
   *
   * @return A shared_pointer to a valid Scheduler implementation.
   */
  static std::shared_ptr<Scheduler> New();

  /**
   * Destructor of the Scheduler.
   */
  virtual ~Scheduler() {}

  /**
   * Synchronous computation.
   * Initiate a Hash and chains the mandatory calls to Update() and Finish()
   *
   * @param s a shared pointer to the data to input string.
   * @return the digest of the input data.
   * @throw std::logic_error upon an error.
   */
  std::string Compute(StringPtr s);

  /**
   * Instantiate a Hash linked to the current Scheduler implementation.
   * @return a pointer (and its ownership) on a valid Hash implementation.
   * @throw std::exception upon an error
   */
  virtual std::unique_ptr<Hash> NewHash() = 0;

  /**
   * Low-Level API
   * Feed the hash with data.
   *
   * @param id the identifier of the stream into the Scheduler implementation
   * @param b
   */
  virtual void Update(uint32_t id, StringPtr b) = 0;

  /**
   * Low-Level API
   * Inform the Hash that no more data is expected.
   *
   * @param id the identifier of the stream into the Scheduler implementation
   * @return a shared future holding the digest
   * @throw std::exception upon an error.
   */
  virtual Digest Finish(uint32_t id) = 0;

  /**
   * Low-Level API
   * Releases the underlying hash to the Scheduler. That hash is unusable
   * afterwards, unless a proper reallocation.
   * Finishes the underlying hash if necessary.
   *
   * @param id the identifier of the stream into the Scheduler implementation
   * @throw std::exception upon an error
   */
  virtual void release(uint32_t id) = 0;

 protected:
  Scheduler() {}

  Scheduler(const Scheduler &o) = delete;

  Scheduler(Scheduler &&o) = delete;
};

/**
 * RAII of a single checksum computation.
 */
class Hash {
 public:
  Hash() = delete;

  Hash(const Hash &o) = delete;

  Hash(Hash &&o) :
      scheduler_(std::move(o.scheduler_)), index_{o.index_} {}

  explicit Hash(std::shared_ptr<Scheduler> srv, uint32_t index) :
      scheduler_(std::move(srv)), index_{index} {}

  ~Hash() {
    scheduler_->release(index_);
  }

  Hash &Update(StringPtr b) {
    scheduler_->Update(index_, std::move(b));
    return *this;
  }

  Digest Finish() {
    return scheduler_->Finish(index_);
  }

 private:
  std::shared_ptr<Scheduler> scheduler_;
  uint32_t index_;
};

}  // namespace isal
}  // namespace md5
}  // namespace hash

#endif  // HASH_ISAL_MD5_HPP_
