// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <iostream>
#include <array>

#include "../src/hash_isal_md5.hpp"

using hash::md5::isal::Scheduler;
using hash::md5::isal::Stream;
using hash::StringPtr;

static StringPtr buffer(new std::string(8192, ':'));

// Early release
TEST(MD5, Scheduler_Release_Init) {
  Scheduler::New();
}

// Early release
TEST(MD5, Stream_Release_Init) {
  auto sched = Scheduler::New();
  sched->MakeStream();
}

// Early release
TEST(MD5, Stream_Release_Update) {
  auto sched = Scheduler::New();
  auto hash = sched->MakeStream();
  hash->Update(buffer);
}

// Early release
TEST(MD5, Stream_Release_Finish) {
  auto sched = Scheduler::New();
  auto hash = sched->MakeStream();
  hash->Finish();
}

// Early release
TEST(MD5, Stream_Release_UpdateFinish) {
  auto sched = Scheduler::New();
  auto hash = sched->MakeStream();
  hash->Update(buffer);
  hash->Finish();
}

// Produces a valid stream and forces the liberation of the Scheduler.
std::unique_ptr<Stream> makeStream() {
  return Scheduler::New()->MakeStream();
}

// Early destruction of the Scheduler
TEST(MD5, Stream_EarlyDestruction_Init) {
  makeStream();
}

// Early destruction of the Scheduler
TEST(MD5, Stream_EarlyDestruction_Update) {
  makeStream()->Update(buffer);
}

// Early destruction of the Scheduler
TEST(MD5, Stream_EarlyDestruction_Finish) {
  makeStream()->Finish();
}

// Early destruction of the Scheduler
TEST(MD5, Stream_EarlyDestruction_UpdateFinish) {
  makeStream()->Update(buffer).Finish();
}

TEST(MD5, SimpleRun) {
  auto sched = Scheduler::New();
  auto hash = sched->MakeStream();
  hash->Update(buffer);
  auto digest = hash->Finish();
  digest.wait();
  digest.get();
}

TEST(MD5, Short) {
  auto hash = Scheduler::New()->MakeStream();
  hash->Update(std::make_shared<std::string>("plop"));
  ASSERT_EQ(hash->Finish().get(),
            "64a4e8faed1a1aa0bf8bf0fc84938d25");
}

TEST(MD5, ShortRepeated) {
  auto hash = Scheduler::New()->MakeStream();
  for (int i{0}; i < 64; i++)
    hash->Update(std::make_shared<std::string>("plop"));
  ASSERT_EQ(hash->Finish().get(),
            "1a6f3663f2766606e794c2d23477aab7");
}

TEST(MD5, ShortThreaded) {
  std::vector<std::thread> threads;
  auto sched = Scheduler::New();
  auto short_string = std::make_shared<std::string>("plop");
  for (int i{0}; i < 256; i++) {
    threads.emplace_back([sched, short_string]() {
      ASSERT_EQ(sched->Compute(short_string),
                "64a4e8faed1a1aa0bf8bf0fc84938d25");
    });
  }
  for (auto &th : threads)
    th.join();
}

int main(int argc, char **argv) {
  (void) argc;

  FLAGS_alsologtostderr = false;
  ::google::InitGoogleLogging(argv[0]);

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
