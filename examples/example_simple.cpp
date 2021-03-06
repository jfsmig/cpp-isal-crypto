// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>
#include <string>

#include "../src/hash_isal_md5.hpp"

using hash::md5::isal::Scheduler;
using hash::md5::isal::Hash;
using hash::StringPtr;

#define N 1024

static StringPtr buffer(new std::string(8192, ':'));

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  auto hash = Scheduler::New()->NewHash();
  for (int i{0}; i < N; i++)
    hash->Update(buffer);
  auto digest = hash->Finish().get();
  std::cout << digest << std::endl;

  return 0;
}
