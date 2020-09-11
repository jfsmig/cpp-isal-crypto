// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <iostream>
#include <array>

#include "../src/hash_isal_md5.hpp"

using hash::md5::isal::SchedulerInterface;
using hash::md5::isal::Stream;
using hash::StringPtr;

static StringPtr buffer(new std::string(8192, ':'));

TEST(MD5, SchedulerInitRelease) {
  SchedulerInterface::New();
}

TEST(MD5, StreamInitRelease) {
  auto server = SchedulerInterface::New();
  server->MakeStream();
}

TEST(MD5, StreamUpdateRelease) {
  auto server = SchedulerInterface::New();
  auto client = server->MakeStream();
  client->Update(buffer);
}

TEST(MD5, StreamFinishRelease) {
  auto server = SchedulerInterface::New();
  auto client = server->MakeStream();
  client->Finish();
}

TEST(MD5, StreamUpdateFinishRelease) {
  auto server = SchedulerInterface::New();
  auto client = server->MakeStream();
  client->Update(buffer);
  client->Finish();
}

TEST(MD5, SimpleRun) {
  auto server = SchedulerInterface::New();
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
