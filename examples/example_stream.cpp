// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>
#include <string>

#include "../src/hash_isal_md5.hpp"

using hash::md5::isal::SchedulerInterface;
using hash::md5::isal::Stream;
using hash::StringPtr;

#define N 8

static StringPtr buffer(new std::string(8192, ':'));

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  auto server = SchedulerInterface::New();

  // Prepare N streams, one for each offset
  std::vector<std::shared_ptr<Stream>> streams;
  for (int i{0}; i < N; i++)
    streams.push_back(server->MakeStream());

  // Feed the N streams, shere the stream 'i' starts
  // checksuming at the line i-th line on the standard input.
  uint32_t i{0};
  std::string line;
  while (std::getline(std::cin, line)) {
    auto buf = std::make_shared<std::string>(line);
    for (typeof(i) j{0}; j < N && j <= i; j++)
      streams[j]->Update(buf);
    i++;
  }

  // Finish all the streams and then collect the results
  std::vector<std::shared_future<std::string>> results;
  for (auto &s : streams)
    results.push_back(s->Finish());
  // FIXME(jfs): should this work? currently it fails miserably.
  streams.clear();
  for (auto &rc : results)
    std::cout << rc.get() << std::endl;

  return 0;
}
