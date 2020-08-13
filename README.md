# C++ wrapper for ``isa-l_crypto``

Attempt to make [isal-crypto]  easy to use.

[isal-crypto]: https://github.com/intel/isa-l_crypto

Made with love by [the Authors](./AUTHORS.md).

## Examples

### Checksuming A Single Stream

```c++
  auto server = SchedulerInterface::New();
  auto stream = server->MakeStream();
  for (int i{0}; i < N; i++)
    stream->Update(buffer);
  auto rc = stream->Finish();
  std::cout << rc.get() << std::endl;
```

### Multiplexed checksums on stdin (mono-thread)

```c++
  // Allocate the scheduler of our few streams
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
    auto buf = std::make_shared<StringBuffer>(line);
    for (typeof(i) j{0}; j < N && j <= i; j++)
      streams[j]->Update(buf);
    i++;
  }

  // Finish all the streams and then collect the results
  std::vector<std::future<std::string>> results;
  for (auto &s : streams)
    results.push_back(s->Finish());
  for (auto &rc : results)
    std::cout << rc.get() << std::endl;
```

### Many Concurrent Checksums (multi-thread)

```c++
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
```