#include <algorithm>
#include <numeric>

#include "./dns_tester.hpp"
#include "./utils.hpp"

namespace dns {

Tester::Tester(const std::string target, const Type query,
               const unsigned int samples, const unsigned int concurrency,
               const bool verbose)
    : target_(target),
      query_(query),
      samples_(samples),
      concurrency_(concurrency),
      verbose_(verbose),
      running_(false) {
    for (int i = 0; i < concurrency; i++) {
        std::thread worker([this] {
#ifndef NDEBUG
            util::debug(std::this_thread::get_id(), " - Launched");
#endif
            {
                std::unique_lock lock(mtx_);
                cond_.wait(lock, [this] { return running_ == true; });
            }
#ifndef NDEBUG
            util::debug(std::this_thread::get_id(), " - Started to work");
#endif

            while (counter_ < samples_) {
                ++counter_;
                doTest();
#ifndef NDEBUG
                util::debug(std::this_thread::get_id(), " - Done");
#endif
            }
        });
        pool_.emplace_back(std::move(worker));
    }
}

void Tester::run() {
    running_ = true;

    cond_.notify_all();
    for (std::thread& worker : pool_) {
        worker.join();
    }
}

std::unique_ptr<TestStats> Tester::report() {
    if (results_.empty()) return nullptr;

    int count = 0;
    int success = 0, failure = 0;

    std::vector<Answer::Metrics> dataset;
    for (std::shared_ptr<Answer> answer : results_) {
        count++;
        if (answer->status == Answer::Ok) {
            success++;
        } else {
            failure++;
        }
        dataset.push_back(answer->metrics);
    }

    sort(dataset.begin(), dataset.end(),
         [](Answer::Metrics a, Answer::Metrics b) {
             return a.elapsed < b.elapsed;
         });

    std::unique_ptr<TestStats> stats = std::make_unique<TestStats>();

    stats->samples = count;

    stats->success = success;
    stats->failure = failure;

    stats->avgTime =
        std::accumulate(dataset.begin(), dataset.end(), 0.0,
                        [&](double acc, Answer::Metrics metrics) {
                            return acc + (metrics.elapsed.count() / count);
                        });
    stats->maxTime = dataset.back().elapsed.count();
    stats->minTime = dataset.front().elapsed.count();
    stats->prctileTime70 = dataset[(dataset.size() - 1) * 0.70].elapsed.count();
    stats->prctileTime80 = dataset[(dataset.size() - 1) * 0.80].elapsed.count();
    stats->prctileTime90 = dataset[(dataset.size() - 1) * 0.90].elapsed.count();
    stats->prctileTime95 = dataset[(dataset.size() - 1) * 0.95].elapsed.count();

    return std::move(stats);
}

void Tester::doTest() {
    std::unique_ptr<Client> client = std::make_unique<Client>();

    client->resolv(target_, query_, false, 1);
    std::shared_ptr<Answer> result = client->answer();

    {
        std::lock_guard lock(mtx_);
        results_.push_back(result);
    }
}
}  // namespace dns