// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include "../src/hash_isal_md5.hpp"

using hash::md5::isal::Scheduler;
using hash::md5::isal::Hash;
using hash::StringPtr;

static StringPtr buf_1KiB(new std::string(1024, ':'));
static StringPtr buf_8KiB(new std::string(8192, ':'));
static StringPtr buf_32KiB(new std::string(32768, ':'));

static void MD5_isal_Scheduler_Lifecycle(benchmark::State &state) {
  for (auto _ : state) {
    Scheduler::New();
  }
}

static void MD5_isal_Stream_Lifecycle(benchmark::State &state) {
  auto sched = Scheduler::New();
  for (auto _ : state) {
    sched->NewHash();
  }
}


static void upload_NStreams_1MiB(std::shared_ptr<Scheduler> sched, int nb, StringPtr buf) {
  std::vector<std::unique_ptr<Hash>> hashes;
  for (int i{0}; i < nb; i++)
    hashes.emplace_back(sched->NewHash());

  const auto rounds = 1024 * 1024 / buf->size();
  for (size_t i{0}; i < rounds; i++) {
    for (auto &h : hashes)
      h->Update(buf);
  }

  std::vector<std::shared_future<std::string>> digests;
  for (auto &h : hashes)
    digests.emplace_back(h->Finish());
  for (auto &d : digests)
    d.wait();
}

static void upload_1MiB(std::shared_ptr<Scheduler> sched, StringPtr buf) {
  return upload_NStreams_1MiB(std::move(sched), 1, std::move(buf));
}

static void MD5_isal_1Stream_1MiB_per_1kiB(benchmark::State &state) {
  auto sched = Scheduler::New();
  for (auto _ : state) {
    upload_1MiB(sched, buf_1KiB);
  }
}

static void MD5_isal_1Stream_1MiB_per_8kiB(benchmark::State &state) {
  auto sched = Scheduler::New();
  for (auto _ : state) {
    upload_1MiB(sched, buf_8KiB);
  }
}

static void MD5_isal_1Stream_1MiB_per_32kiB(benchmark::State &state) {
  auto sched = Scheduler::New();
  for (auto _ : state) {
    upload_1MiB(sched, buf_32KiB);
  }
}


static void MD5_isal_4Stream_1MiB_per_1kiB(benchmark::State &state) {
  auto sched = Scheduler::New();
  for (auto _ : state) {
    upload_NStreams_1MiB(sched, 4, buf_1KiB);
  }
}

static void MD5_isal_4Stream_1MiB_per_8kiB(benchmark::State &state) {
  auto sched = Scheduler::New();
  for (auto _ : state) {
    upload_NStreams_1MiB(sched, 4, buf_8KiB);
  }
}

static void MD5_isal_4Stream_1MiB_per_32kiB(benchmark::State &state) {
  auto sched = Scheduler::New();
  for (auto _ : state) {
    upload_NStreams_1MiB(sched, 4, buf_32KiB);
  }
}

// Register the function as a benchmark
BENCHMARK(MD5_isal_Scheduler_Lifecycle);
BENCHMARK(MD5_isal_Stream_Lifecycle);
BENCHMARK(MD5_isal_1Stream_1MiB_per_1kiB);
BENCHMARK(MD5_isal_1Stream_1MiB_per_8kiB);
BENCHMARK(MD5_isal_1Stream_1MiB_per_32kiB);
BENCHMARK(MD5_isal_4Stream_1MiB_per_1kiB);
BENCHMARK(MD5_isal_4Stream_1MiB_per_8kiB);
BENCHMARK(MD5_isal_4Stream_1MiB_per_32kiB);

// Run the benchmark
BENCHMARK_MAIN();