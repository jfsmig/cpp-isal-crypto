// Copyright (C) 2020 The authors of cpp-isal-crypto
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

static void BM_Unit_Isal(benchmark::State& state) {
  for (auto _ : state) {
    // TODO(jfsmig)
  }
}
// Register the function as a benchmark
BENCHMARK(BM_Unit_Isal);

// Run the benchmark
BENCHMARK_MAIN();