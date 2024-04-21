#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "./dns_client.hpp"

namespace dns {

struct TestStats {
    int samples;

    int success;
    int failure;

    double avgTime;
    double maxTime;
    double minTime;
    double prctileTime70;
    double prctileTime80;
    double prctileTime90;
    double prctileTime95;
};

class Tester {
public:
    Tester(const std::string target, const Type query,
           const unsigned int samples, const unsigned int concurrency = 1,
           const bool verbose = false);
    void run();
    std::unique_ptr<TestStats> report();

private:
    const std::string target_;
    const Type query_;

    const unsigned int concurrency_;
    const unsigned int samples_;

    const bool verbose_;

    std::vector<std::thread> pool_;

    // mutex is supposed to be used for 2 purposes.
    // 1. lock threads while creating a thread pool.
    // 2. lock to record DNS answers on vector<>.
    std::mutex mtx_;
    std::condition_variable cond_;

    std::atomic<bool> running_;
    std::atomic<int> counter_;

    std::vector<std::shared_ptr<Answer>> results_;

    void doTest();
};
}  // namespace dns