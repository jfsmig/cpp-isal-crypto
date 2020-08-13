// Copyright (C) 2020 The authors of cpp-isal-crypto.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "hash_isal_md5.hpp"
#include <exception>
#include "glog/logging.h"

using hash::Buffer;
using hash::md5::isal::Stream;
using hash::md5::isal::SchedulerInterface;

enum class State {
  // Ready to be Reserved to a stream
  Idle = 0,

  // Reserved to a stream but not initiated yet
  // Out of the waiting line
  Reserved,

  // Reserved to a stream but not initiated yet
  // In the waiting line
  Reserved_Waiting,

  // Reserved to a stream, initiated but no computation active
  // Out of the waiting line
  Ready,

  // Reserved to a stream, initiated but no computation active
  // In the waiting line
  Ready_Waiting,

  // Reserved to a stream, a (first / middle) computation is currently running
  Active,

  // Reserved to a stream, a (last) computation is currently running
  Finishing,

  // Reserved to a stream, no computation pending, no new data
  // accepted.
  Finished,
};

class Scheduler;

struct StreamEntry {
  MD5_HASH_CTX hasher_;
  State state_;
  uint32_t index_;
  std::queue<std::shared_ptr<Buffer>> pending_blocks_;
  std::shared_ptr<Buffer> current_block_;
  std::promise<std::string> result_;

  StreamEntry() : hasher_{}, state_{State::Idle} { hasher_.user_data = this; }
};

class Scheduler : public SchedulerInterface {
 public:
  ~Scheduler();

  Scheduler();

  std::shared_ptr<Stream> MakeStream() override;

 protected:
  void stream_update(uint32_t id, std::shared_ptr<Buffer> buffer) override;

  std::future<std::string> stream_finish(uint32_t id) override;

  void stream_release(uint32_t id) override;

 private:
  /**
   * Notify the background routine that there is a new buffer to be considered.
   */
  void poke();

  /* Main execution loop of the ISA-L core. Loop forwards to backround_step() */
  void background_run();

  /* Main execution routine, doing all the nasty stuff. */
  void backround_step();

  /* Wait for a lane to become available in the ISA-L core. */
  void background_wait_for_lane();

  /* Wait for a poke() indicating that new data is available for any stream. */
  void background_wait_for_poke();

  /**
   * Poll the next waiting client and forward the call to background_stream_trigger()
   */
  void background_stream_trigger_first();

  /**
   * Execute the next action of the given stream.
   *
   * @param stream a pointer to a valid stream, whose state must be "*_WAITING"
   */
  void background_stream_trigger(StreamEntry *stream);

  /**
   * Manage the result of a submitted job in the ISA-L scheduler.
   * @param stream a pointer to a valid stream, whose state must tell it is ACTIVE/FINISHING
   */
  void background_stream_completion(StreamEntry *stream);

 private:
  MD5_HASH_CTX_MGR manager_;

  std::mutex mutex_;
  std::unique_lock<std::mutex> lock_;
  std::condition_variable barrier_;

  std::array<StreamEntry, 1024> streams_;
  std::queue<uint32_t> streams_indexes_pending_;
  std::queue<uint32_t> streams_indexes_idle_;

  uint32_t nb_streams_active_;

  uint32_t max_lanes_;
  std::thread worker_;
  bool flag_running_;
};


Stream::~Stream() {
  scheduler_->stream_release(index_);
}

std::future<std::string> Stream::Finish() {
  return scheduler_->stream_finish(index_);
}

void Stream::Update(std::shared_ptr<Buffer> b) {
  return scheduler_->stream_update(index_, std::move(b));
}


std::shared_ptr<SchedulerInterface> SchedulerInterface::New() {
  return std::make_shared<Scheduler>();
}

Scheduler::Scheduler() :
    manager_{},
    mutex_(), lock_(mutex_), barrier_(),
    streams_(), streams_indexes_pending_(), streams_indexes_idle_(),
    nb_streams_active_{0},
    max_lanes_{MD5_MAX_LANES},
    worker_{},
    flag_running_{true} {
  md5_ctx_mgr_init(&manager_);
  uint32_t i{0};
  for (auto &c : streams_) {
    c.index_ = i++;
    streams_indexes_idle_.push(c.index_);
  }
  worker_ = std::thread([this]() { this->background_run(); });
}

Scheduler::~Scheduler() {
  LOG(ERROR) << __func__;
  flag_running_ = false;
  barrier_.notify_one();
  worker_.join();
  LOG(ERROR) << __func__ << " background thread joined";
}

std::shared_ptr<Stream> Scheduler::MakeStream() {
  LOG(ERROR) << __func__;
  uint32_t idx = streams_indexes_idle_.back();
  streams_indexes_idle_.pop();
  return std::make_shared<Stream>(this, idx);
}

void Scheduler::poke() {
  LOG(ERROR) << __func__;
  barrier_.notify_one();
}

void Scheduler::background_run() {
  LOG(ERROR) << __func__ << " running";
  while (flag_running_) {
    backround_step();
  }

  // closing phase
  LOG(ERROR) << __func__ << " closing";
  while (streams_indexes_idle_.size() != streams_.size()) {
    backround_step();
  }

  LOG(ERROR) << __func__ << " exiting";
}

void Scheduler::backround_step() {
  LOG(ERROR) << __func__;
  std::lock_guard section(lock_);
  if (nb_streams_active_ <= 0) {
    // If there is no active stream, then check there are pending streams
    // and if there is none, then wait for a notification
    if (streams_indexes_pending_.empty()) {
      background_wait_for_poke();
      assert(!streams_indexes_pending_.empty());
    }
    return background_stream_trigger_first();
  } else if (nb_streams_active_ < max_lanes_) {
    // Lanes remain, so we just try to start a new stream
    if (streams_indexes_pending_.empty()) {
      return background_wait_for_lane();
    } else {
      return background_stream_trigger_first();
    }
  } else {
    // No lane remain, we just need a slot to be released.
    return background_wait_for_lane();
  }
}

void Scheduler::background_stream_trigger_first() {
  LOG(ERROR) << __func__;
  auto id = streams_indexes_pending_.front();
  streams_indexes_pending_.pop();
  return background_stream_trigger(&streams_.at(id));
}

void Scheduler::background_stream_trigger(StreamEntry *stream) {
  MD5_HASH_CTX *ctx{nullptr};
  std::shared_ptr<Buffer> buf;
  StreamEntry *done{nullptr};
  auto flags{HASH_UPDATE};

  LOG(ERROR) << __func__;
  assert(stream == stream->hasher_.user_data);

  switch (stream->state_) {
    case State::Idle:
    case State::Active:
    case State::Finishing:
    case State::Finished:
      throw std::logic_error("BUG: no activity expected");

    case State::Reserved:
    case State::Ready:
      throw std::logic_error("BUG: not waiting in the line");

    case State::Reserved_Waiting:
      flags = HASH_FIRST;
      // FALLTHROUGH
    case State::Ready_Waiting:
      assert(stream->current_block_.get() != nullptr);
      stream->state_ = State::Active;
      ctx = md5_ctx_mgr_submit(&manager_, &stream->hasher_,
                               buf->data(), buf->size(), flags);
      done = reinterpret_cast<StreamEntry *>(ctx->user_data);
      if (done != nullptr) {
        background_stream_completion(done);
      }
      return;
  }
}

void Scheduler::background_stream_completion(StreamEntry *stream) {
  assert(nb_streams_active_ > 0);
  nb_streams_active_--;
  stream->current_block_.reset();

  switch (stream->state_) {
    case State::Finishing:
      assert(stream->pending_blocks_.empty());
      stream->state_ = State::Finished;
      return;
    case State::Active:
      if (stream->pending_blocks_.empty()) {
        stream->state_ = State::Ready;
      } else {
        stream->state_ = State::Ready_Waiting;
        streams_indexes_pending_.push(stream->index_);
      }
      return;
    default:
      throw std::logic_error("BUG: completion for inactive stream");
  }
}

void Scheduler::background_wait_for_lane() {
  LOG(ERROR) << __func__;
  for (;;) {
    DECLARE_ALIGNED(MD5_HASH_CTX ctx, sizeof(void *));
    hash_ctx_init(&ctx);

    nb_streams_active_++;
    auto ptr = md5_ctx_mgr_submit(&manager_, &ctx, nullptr, 0, HASH_FIRST);

    if (ptr != nullptr) {
      if (ptr == &ctx) {
        throw std::logic_error("NYI");
      } else {
        auto se = reinterpret_cast<StreamEntry *>(ptr);
        return background_stream_completion(se);
      }
    }
    auto quantum = std::chrono::duration<int, std::micro>(100);
    std::this_thread::sleep_for(quantum);
  }
}

void Scheduler::background_wait_for_poke() {
  LOG(ERROR) << __func__;
  barrier_.wait(lock_);
}

void Scheduler::stream_update(uint32_t id, std::shared_ptr<Buffer> buffer) {
  auto &stream = streams_.at(id);
  switch (stream.state_) {
    case State::Idle:
      throw std::logic_error("BUG: update() not allowed on idle stream");

    case State::Reserved:
      stream.state_ = State::Reserved_Waiting;
      streams_indexes_pending_.push(stream.index_);
      // FALLTHROUGH
    case State::Reserved_Waiting:
      stream.pending_blocks_.push(std::move(buffer));
      poke();
      return;

    case State::Ready:
      stream.state_ = State::Ready_Waiting;
      stream.pending_blocks_.push(std::move(buffer));
      // FALLTHROUGH
    case State::Ready_Waiting:
      stream.pending_blocks_.push(std::move(buffer));
      poke();
      return;

    case State::Active:
      stream.pending_blocks_.push(std::move(buffer));
      return;

    case State::Finishing:
      throw std::logic_error("BUG: update() not allowed on finishing stream");

    case State::Finished:
      throw std::logic_error("BUG: update() not allowed on finished stream");
  }
}

std::future<std::string> Scheduler::stream_finish(uint32_t id) {
  LOG(ERROR) << __func__;
  // return streams_.at(id).result_.get_future();
  auto &stream = streams_.at(id);
  (void) stream;
  throw std::logic_error("NYI");
}

void Scheduler::stream_release(uint32_t id) {
  LOG(ERROR) << __func__;
  auto &stream = streams_.at(id);
  switch (stream.state_) {
    case State::Idle:
      throw std::logic_error("BUG: cannot release an idle stream");
    case State::Active:
    case State::Finishing:
      throw std::logic_error("NYI: releasing a stream while active");
    case State::Ready_Waiting:
    case State::Reserved_Waiting:
      throw std::logic_error("NYI: releasing a stream while waiting");
    case State::Ready:
    case State::Reserved:
    case State::Finished:
      while (!stream.pending_blocks_.empty())
        stream.pending_blocks_.pop();
      stream.current_block_.reset();
      stream.state_ = State::Idle;
      return;
  }
}
