#include <iostream>
#include <iomanip>

#include <boost/program_options.hpp>

#include "config.h"
#include "./dns_client.hpp"
#include "./dns_tester.hpp"
#include "./utils.hpp"

namespace bpo = boost::program_options;

int main(int argc, char** argv) {
    bpo::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "print help messages")
        ("verbose,v", "be verbose")
        ("type,q", bpo::value<std::string>()->default_value("A"), "type of DNS queries")
        ("count,c", bpo::value<int>()->default_value(1), "number of DNS queries")
        ("thread_num,t", bpo::value<int>()->default_value(1), "number of threads in each process")
        // TODO: implement multi-porcesses soon
        // ("process_num,p", bpo::value<int>()->default_value(1), "number of processes")
        ("version", "print version")
        ("check", "send single query and show answer")
        ("domain",  "target domain e.g. www.google.com")
    ;

    bpo::positional_options_description p;
    p.add("domain", -1);

    bpo::variables_map vm;
    bpo::store(
        bpo::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    bpo::notify(vm);

    if (vm.count("version")) {
        std::cout << DNS_BENCHMARK_VERSION << std::endl;
        return 1;
    } else if (vm.count("help") || !vm.count("domain")) {
        std::cout << desc << std::endl;
        return 1;
    }

    std::string domain = vm["domain"].as<std::string>();
    std::string type = util::uppercase(vm["type"].as<std::string>());

    dns::Type query;
    if (type == "AAAA") {
        query = dns::AAAA;
    } else if (type == "PTR") {
        query = dns::PTR;
    } else if (type == "CNAME") {
        query = dns::CNAME;
    } else if (type == "MX") {
        query = dns::MX;
    } else if (type == "TXT") {
        query = dns::TXT;
    } else {
        query = dns::A;
    }

    if (vm.count("check")) {
        dns::Client* client = new dns::Client();
        client->resolv(domain, query);
        return 0;
    }

    std::unique_ptr<dns::Tester> tester = std::make_unique<dns::Tester>(
        /* domain */ domain,
        /* query */ query,
        /* samples */ vm["count"].as<int>(),
        /* concurrency */ vm["thread_num"].as<int>(),
        /* verbose */ vm.count("verbose"));

    tester->run();

    std::unique_ptr<dns::TestStats> stats = tester->report();

    std::cout << "Target Domain: " << domain << " (" << type << ")" << std::endl;
    std::cout << "--------------------------------------" << std::endl;
    std::cout << "Avg Answer Time (ms): " << std::fixed << std::setprecision(3) << stats->avgTime << std::endl;
    std::cout << "Max Answer Time (ms): " << std::fixed << std::setprecision(3) << stats->maxTime << std::endl;
    std::cout << "Min Answer Time (ms): " << std::fixed << std::setprecision(3) << stats->minTime << std::endl;
    std::cout << "70th Answer Time (ms): " << std::fixed << std::setprecision(3) << stats->prctileTime70 << std::endl;
    std::cout << "80th Answer Time (ms): " << std::fixed << std::setprecision(3) << stats->prctileTime80 << std::endl;
    std::cout << "90th Answer Time (ms): " << std::fixed << std::setprecision(3) << stats->prctileTime90 << std::endl;
    std::cout << "95th Answer Time (ms): " << std::fixed << std::setprecision(3) << stats->prctileTime95 << std::endl;
    std::cout << "(" << stats->samples << " queries)" << std::endl;

    return 0;
}
