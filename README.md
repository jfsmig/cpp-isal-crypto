# C++ wrapper for ``isa-l_crypto``

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/baa309c34cfe4868b3632b6dd87eada6)](https://app.codacy.com/manual/jfsmig/cpp-isal-crypto?utm_source=github.com&utm_medium=referral&utm_content=jfsmig/cpp-isal-crypto&utm_campaign=Badge_Grade_Dashboard)
[![CircleCI](https://circleci.com/gh/jfsmig/cpp-isal-crypto.svg?style=shield)](https://app.circleci.com/pipelines/github/jfsmig/cpp-isal-crypto)

Attempt to make [isal-crypto] easy to use.

Made with love by [the Authors](./AUTHORS.md).

## Examples

### Checksuming A Single Hash

```c++
  auto hash = Scheduler::New()->NewHash();
  for (int i{0}; i < N; i++)
    hash->Update(buffer);
  auto digest = hash->Finish().get();
  std::cout << digest << std::endl;
```

### Multiplexed checksums on stdin (mono-thread)

```c++
  auto sched = Scheduler::New();

  // Prepare N streams, one for each offset
  std::vector<std::unique_ptr<Hash>> hashes;
  for (int i{0}; i < N; i++)
    hashes.emplace_back(sched->NewHash());

  // Feed the N streams, there the stream 'i' starts checksum'ing
  // at the line i-th line on the standard input. Without data copies.
  std::string line;
  for (uint32_t i{0}; std::getline(std::cin, line); i++) {
    auto buf = std::make_shared<std::string>(line);
    for (typeof(i) j{0}; j < N && j <= i; j++)
      hashes[j]->Update(buf);
  }

  // Finish all the streams and then collect the results
  std::vector<Digest> digests;
  for (auto &s : hashes)
    digests.push_back(s->Finish());
  for (auto &digest : digests)
    std::cout << digest.get() << std::endl;
```

### Many Concurrent Checksums (multi-thread)

```c++
  // Allocate the scheduler of our many streams
  auto sched = Scheduler::New();

  // Spawn many concurrent computations
  std::vector<std::thread> threads;
  for (int i{0}; i < N; i++) {
    threads.emplace_back([sched]() {
      auto hash = sched->MakeStream();
      hash->Update(buffer);
      auto digest = hash->Finish().get();
      std::cout << digest << std::endl;
    });
  }

  // Wait for all the computation to terminate
  for (auto &th : threads)
    th.join();
```

[isal-crypto]: https://github.com/intel/isa-l_crypto
