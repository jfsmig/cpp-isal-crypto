// Copyright (C) 2020 The authors of cpp-isal-crypto.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "hash_isal_md5.hpp"
#include <exception>
#include "glog/logging.h"

using hash::StringPtr;
using hash::md5::isal::Stream;
using hash::md5::isal::SchedulerInterface;

static StringPtr empty = std::make_shared<std::string>("");

enum class State {
  // Unused stream.
  // The only allowed action is to reserve it to a stream.
  Idle = 0,

  // -------------------------------------------------------------------------
  // All the Ready_* states have in common that the stream has no pending data,
  // thus it cannot be in the waiting queue.
  // -------------------------------------------------------------------------

  // Not initiated yet, upon the next block it will be necessary to initiate
  // the checksum structure.
  Ready_First = 1,

  // Already initiated yet, upon the next block it is only necessary to update
  // the checksum structure.
  Ready_Update = 2,

  // -------------------------------------------------------------------------
  // All the Queued_* states have in common that the stream is waiting in the
  // queue for a computing slot, ad they should have a non-empty queue of
  // pending blocks.
  // -------------------------------------------------------------------------

  // First block received (the queue might contain more). The computation will
  // apply the ~FIRST call to initiate the checksum structure on the first
  // item of the queue of pending blocks.
  Queued_First = 3,

  // Middle block received (the queue length might be longer than 1). The next
  // computation will just ~UPDATE the checksum structure.
  Queued_Update = 4,

  // Last block received (the queue length might be longer than 1). If the size
  // of the queue is 1, the next computation will apply the ~LAST call on the
  // checksum structure. Otherwise, the computation will apply the ~UPDATE call
  // on the first element of the queue.
  Queued_Last = 5,

  // Last block received on a stream tha has not been initiated yet. In other
  // words, the whole content is in the queue of pending blocks (whose length
  // might be greater than 1). The implementation will chain calls with FIRST,
  // UPDATE, LAST if the size of the queue is > 1, and will apply a single WHOLE
  // call of the size is exactly 1.
  Queued_Whole = 6,

  // -------------------------------------------------------------------------
  // All the Computing_* states share that a computation is pending on the
  // current stream. They must not be in the queue of waiting blocks.
  // -------------------------------------------------------------------------

  // The computation happens on a stream that didn't received the final blocks
  // yet. Thus when the computation will end, depending on the presence of
  // pending blocks, the stream will return in a Ready_Update of a Queued_Update
  // state.
  Computing_Update = 7,

  // The computation happens on a stream that received its final block. When
  // the computation will end, the stream will return in either the Ready_Last
  // or the Queued_Last, depending on the availability of blocks in the pending
  // queue.
  Computing_Last = 8,

  // -------------------------------------------------------------------------

  // The checksum is complete, the stream must not appear in the waiting line
  // for a computation. Neither should it have pending blocks.
  // The digest is available and the stream is ready to be released.
  Finished = 9,
};

class Scheduler;

/**
 * A StreamEntry is the footprint of a checksum computation in the Scheduler.
 *
 */
struct StreamEntry {
  MD5_HASH_CTX hasher_;
  uint32_t index_;
  State state_;
  std::queue<StringPtr> pending_blocks_;
  std::promise<std::string> result_;

  StreamEntry() : hasher_{}, state_{State::Idle} { hasher_.user_data = this; }

  void check(State s) {
    assert(state_ == s);
    check();
  }

  void check() const {
    assert(this == hasher_.user_data);
    switch (state_) {
      case State::Idle:
      case State::Ready_First:
      case State::Ready_Update:
      case State::Finished:
        assert(pending_blocks_.empty());
        return;
      case State::Queued_First:
      case State::Queued_Update:
      case State::Queued_Last:
      case State::Queued_Whole:
      case State::Computing_Update:
      case State::Computing_Last:
        assert(!pending_blocks_.empty());
        return;
      default:
        assert(state_ >= State::Idle && state_ <= State::Finished);
        abort();
    }
  }

  void flush() {
    while (!pending_blocks_.empty())
      pending_blocks_.pop();
  }
};

class Scheduler : public SchedulerInterface {
 public:
  ~Scheduler();

  Scheduler();

  std::shared_ptr<Stream> MakeStream() override;

 protected:
  void stream_update(uint32_t id, StringPtr b) override;

  std::future<std::string> stream_finish(uint32_t id) override;

  void stream_release(uint32_t id) noexcept override;

 private:
  // Notify the background routine that there is a new buffer to be considered.
  void poke();

  // Main execution loop of the ISA-L core. Loop forwards to backround_step()
  void background_run();

  // Main execution routine, doing all the nasty stuff.
  void backround_step();

  // Wait for a lane to become available in the ISA-L core.
  void background_wait_for_lane();

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
  std::condition_variable barrier_;

  std::array<StreamEntry, 8192> streams_;
  std::queue<uint32_t> streams_indexes_pending_;
  std::queue<uint32_t> streams_indexes_idle_;

  std::atomic<uint32_t> nb_computations_;

  uint32_t max_lanes_;
  std::thread worker_;
  std::atomic<bool> flag_running_;
};


Stream::~Stream() {
  scheduler_->stream_release(index_);
}

std::future<std::string> Stream::Finish() {
  return scheduler_->stream_finish(index_);
}

void Stream::Update(StringPtr b) {
  return scheduler_->stream_update(index_, std::move(b));
}


std::shared_ptr<SchedulerInterface> SchedulerInterface::New() {
  return std::make_shared<Scheduler>();
}

Scheduler::Scheduler() :
    manager_{},
    mutex_(), barrier_(),
    streams_(), streams_indexes_pending_(), streams_indexes_idle_(),
    nb_computations_{0},
    max_lanes_{MD5_MAX_LANES},
    worker_{},
    flag_running_{true} {
  LOG(ERROR) << __func__;
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

  auto &stream = streams_.at(idx);
  stream.check(State::Idle);
  stream.state_ = State::Ready_First;

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
  std::unique_lock lock{mutex_};
  if (nb_computations_ <= 0) {
    // If there is no active stream, then check there are pending streams
    // and if there is none, then wait for a notification
    if (streams_indexes_pending_.empty()) {
      barrier_.wait(lock);
    } else {
      return background_stream_trigger_first();
    }
  } else if (nb_computations_ < max_lanes_) {
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
  if (streams_indexes_pending_.empty())
    return;
  auto id = streams_indexes_pending_.front();
  streams_indexes_pending_.pop();
  return background_stream_trigger(&streams_.at(id));
}

void Scheduler::background_stream_trigger(StreamEntry *stream) {
  MD5_HASH_CTX *ctx{nullptr};
  StringPtr buf;
  StreamEntry *done{nullptr};
  auto flags{HASH_UPDATE};

  LOG(ERROR) << __func__;
  stream->check();

  switch (stream->state_) {
    case State::Idle:
    case State::Computing_Update:
    case State::Computing_Last:
    case State::Finished:
      throw std::logic_error("BUG: no activity expected");

    case State::Ready_First:
    case State::Ready_Update:
      throw std::logic_error("BUG: not waiting in the line");

    case State::Queued_First:
      flags = HASH_FIRST;
      // FALLTHROUGH
    case State::Queued_Whole:
    case State::Queued_Last:
    case State::Queued_Update:
      stream->state_ = State::Computing_Update;
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
  assert(nb_computations_ > 0);
  nb_computations_--;

  switch (stream->state_) {
    case State::Queued_Last:
      assert(stream->pending_blocks_.empty());
      stream->state_ = State::Finished;
      return;
    case State::Computing_Update:
      if (stream->pending_blocks_.empty()) {
        stream->state_ = State::Ready_Update;
      } else {
        stream->state_ = State::Queued_Update;
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

    nb_computations_++;
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

void Scheduler::stream_update(uint32_t id, StringPtr b) {
  auto &stream = streams_.at(id);
  stream.check();
  poke();
  switch (stream.state_) {
    case State::Idle:
      throw std::logic_error("BUG: update() not allowed on idle stream");

    case State::Ready_First:
      stream.state_ = State::Queued_First;
      streams_indexes_pending_.push(stream.index_);
      return stream.pending_blocks_.push(std::move(b));

    case State::Ready_Update:
      stream.state_ = State::Queued_Update;
      streams_indexes_pending_.push(stream.index_);
      return stream.pending_blocks_.push(std::move(b));

    case State::Queued_First:
    case State::Queued_Update:
      return stream.pending_blocks_.push(std::move(b));

    case State::Queued_Last:
    case State::Queued_Whole:
      throw std::logic_error("BUG: update() not allowed on finishing stream");

    case State::Computing_Update:
      return stream.pending_blocks_.push(std::move(b));

    case State::Computing_Last:
      throw std::logic_error("BUG: update() not allowed on finishing stream");

    case State::Finished:
      throw std::logic_error("BUG: update() not allowed on finished stream");
  }

  throw std::logic_error("BUG: update() on unhandled state");
}

std::future<std::string> Scheduler::stream_finish(uint32_t id) {
  LOG(ERROR) << __func__;
  auto &stream = streams_.at(id);
  stream.check();
  switch (stream.state_) {
    case State::Idle:
      throw std::logic_error("BUG: finish() not allowed on idle stream");

    case State::Ready_First:
      stream.state_ = State::Queued_Whole;
      stream.pending_blocks_.push(empty);
      streams_indexes_pending_.push(stream.index_);
      return stream.result_.get_future();

    case State::Ready_Update:
      stream.state_ = State::Queued_Last;
      stream.pending_blocks_.push(empty);
      streams_indexes_pending_.push(stream.index_);
      return stream.result_.get_future();

    case State::Queued_First:
      stream.state_ = State::Queued_Whole;
      return stream.result_.get_future();

    case State::Queued_Update:
      stream.state_ = State::Queued_Last;
      return stream.result_.get_future();

    case State::Queued_Last:
    case State::Queued_Whole:
      throw std::logic_error("BUG: finish() not allowed on finishing stream");

    case State::Computing_Update:
      stream.state_ = State::Computing_Last;
      return stream.result_.get_future();

    case State::Computing_Last:
      throw std::logic_error("BUG: finish() not allowed on finishing stream");

    case State::Finished:
      throw std::logic_error("BUG: finish() not allowed on finished stream");
  }
  throw std::logic_error("BUG: finish() on unhandled state");
}

void Scheduler::stream_release(uint32_t id) noexcept {
  LOG(ERROR) << __func__;

  do {  // STEP 1
    std::lock_guard lock{mutex_};
    auto &stream = streams_.at(id);
    stream.check();
    try {
      switch (stream.state_) {
        case State::Idle:
          throw std::logic_error("BUG: release() on an idle stream");
        case State::Queued_First:
        case State::Queued_Update:
        case State::Queued_Last:
        case State::Queued_Whole:
          // The queue doesn't allow us to remove an element efficiently, so we void
          // the computation order but we let it happen.
          stream.flush();
          stream.pending_blocks_.push(empty);
          // FALLTHROUGH
        case State::Computing_Update:
        case State::Computing_Last:
          break;

        case State::Ready_First:
        case State::Ready_Update:
          stream.flush();
          // FALLTHROUGH
        case State::Finished:
          stream.state_ = State::Idle;
          return;
      }
      throw std::logic_error("BUG: release() on unhandled state");
    } catch (std::logic_error &e) {
      LOG(ERROR) << "Failed to release the stream " << id << ": " << e.what();
    }
  } while (0);

  try {
    stream_finish(id).wait();
  } catch (std::logic_error &e) {
    LOG(ERROR) << "Failed to release the stream " << id << ": " << e.what();
  }

  try {
    std::lock_guard section{mutex_};
    auto &stream = streams_.at(id);
    stream.check(State::Finished);
    stream.state_ = State::Idle;
  } catch (std::logic_error &e) {
    LOG(ERROR) << "Failed to release the stream " << id << ": " << e.what();
  }

}
