// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <iostream>
#include <array>

#include "../src/hash_isal_md5.hpp"

static std::array<uint8_t, 8192> blob;

static std::shared_ptr<hash::StaticBuffer> buffer(
    new hash::StaticBuffer(blob.data(), blob.size()));

TEST(MD5, SimpleRun) {
  auto server = hash::md5::isal::SchedulerInterface::New();
  auto client = server->MakeStream();
  client->Update(buffer);
  auto rc = client->Finish();
  rc.wait();
  std::cout << rc.get() << std::endl;
}

int main(int argc, char **argv) {
  (void) argc;

  FLAGS_alsologtostderr = false;
  ::google::InitGoogleLogging(argv[0]);

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}