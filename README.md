# C++ wrapper for ``isa-l_crypto``

Attempt to make [isal-crypto]  easy to use.

[isal-crypto]: https://github.com/intel/isa-l_crypto

Made with love by [the Authors](./AUTHORS.md).

## Examples

### Multiple checksums on stdin

```c++
  auto server = SchedulerInterface::New();

  // Prepare N streams, where the stream 'i' starts checksuming at line 'i'
  std::vector<std::shared_ptr<Stream>> streams;
  for (int i{0}; i<8; i++)
    streams.push_back(server->MakeStream());

  uint32_t i{0};
  std::string line;
  while (std::getline(std::cin, line)) {
    auto buf = std::make_shared<StringBuffer>(line);
    for (typeof(i) j{0}; j<8 && j<=i; j++)
      streams[j]->Update(buf);
    i++;
  }

  std::vector<std::future<std::string>> results;
  for (auto &s : streams)
    results.push_back(s->Finish());

  // FIXME(jfs): should this work? currently it fails miserably.
  streams.clear();

  for (auto &rc : results)
    std::cout << rc.get() << std::endl;
```

### Many Concurrent Checksums

```c++
// Prepare a block to be pushed.
std::array<uint8_t, 8192> blob;
  // Prepare a block to be pushed.
  std::shared_ptr<hash::StaticBuffer> buffer(
      new hash::StaticBuffer(blob.data(), blob.size()));

  // Allocate
  auto server = hash::md5::isal::SchedulerInterface::New();

  // Spawn many concurrent computations
  std::vector<std::thread> threads;
  for (int i{0}; i < 1024; i++) {
    threads.emplace_back([server, buffer]() {
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
```