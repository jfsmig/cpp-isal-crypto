// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>
#include <string>

#include "../src/hash_isal_md5.hpp"

using hash::md5::isal::SchedulerInterface;
using hash::md5::isal::Stream;
using hash::StringBuffer;

#define N 1024

static std::array<uint8_t, 8192> blob;

static std::shared_ptr<hash::StaticBuffer> buffer(
    new hash::StaticBuffer(blob.data(), blob.size()));

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  auto server = SchedulerInterface::New();
  auto stream = server->MakeStream();
  for (int i{0}; i < N; i++)
    stream->Update(buffer);
  auto rc = stream->Finish();
  std::cout << rc.get() << std::endl;

  return 0;
}