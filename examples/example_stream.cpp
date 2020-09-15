// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>
#include <string>
#include <utility>

#include "../src/hash_isal_md5.hpp"

using hash::md5::isal::Scheduler;
using hash::md5::isal::Stream;
using hash::StringPtr;

#define N 8

static StringPtr buffer(new std::string(8192, ':'));

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  auto sched = Scheduler::New();

  // Prepare N streams, one for each offset
  std::vector<std::unique_ptr<Stream>> hashes;
  for (int i{0}; i < N; i++)
    hashes.emplace_back(sched->MakeStream());

  // Feed the N streams, there the stream 'i' starts checksum'ing
  // at the line i-th line on the standard input. Without data copies.
  std::string line;
  for (uint32_t i{0}; std::getline(std::cin, line); i++) {
    auto buf = std::make_shared<std::string>(line);
    for (typeof(i) j{0}; j < N && j <= i; j++)
      hashes[j]->Update(buf);
  }

  // Finish all the streams and then collect the results
  std::vector<std::shared_future<std::string>> digests;
  for (auto &s : hashes)
    digests.push_back(s->Finish());
  for (auto &digest : digests)
    std::cout << digest.get() << std::endl;

  return 0;
}
