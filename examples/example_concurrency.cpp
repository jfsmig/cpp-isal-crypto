// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <array>
#include <vector>
#include <thread>
#include <iostream>

#include "../src/hash_isal_md5.hpp"

#define N 1024

using hash::md5::isal::SchedulerInterface;
using hash::StaticBuffer;

// Prepare a block to be pushed.
static std::array<uint8_t, 8192> blob;
static std::shared_ptr<StaticBuffer> buffer(
    new StaticBuffer(blob.data(), blob.size()));

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  // Allocate the scheduler of our many streams
  auto server = SchedulerInterface::New();

  // Spawn many concurrent computations
  std::vector<std::thread> threads;
  for (int i{0}; i < N; i++) {
    threads.emplace_back([server]() {
      auto client = server->MakeStream();
      client->Update(buffer);
      auto rc = client->Finish();
      std::cout << rc.get() << std::endl;
    });
  }

  // Wait for all the computation to terminate
  for (auto &th : threads)
    th.join();
  threads.clear();

  return 0;
}