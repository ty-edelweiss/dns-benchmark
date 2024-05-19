#pragma once

#include <memory>
#include <string>
#include <vector>
#include <chrono>

#define DNS_BUFFER_SIZE 512
#define EDNS0_BUFFER_SIZE 4096

#define DNS_PORT 53
#define DNS_RESOLVFILE "/etc/resolv.conf"

namespace dns {

enum Type {
    A,
    AAAA,
    PTR,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
};

struct Answer {
    enum Status { Ok, Error };

    struct Record {
        std::string name;
        Type type;
        std::string data;
        std::string other;
        std::vector<int> attr;
        size_t size;
    };

    struct OptRecord {
        size_t udp;
        int version;
        bool dnssec;
    };

    struct Metrics {
        std::chrono::duration<double, std::milli> elapsed;
        size_t total;
    };

    Status status;

    bool authority;
    bool recurse;
    bool edns;

    int count;
    std::vector<Record> records;
    OptRecord opt;

    // DNS metrics
    Metrics metrics;
};

class ConfigLoader {
public:
    static ConfigLoader& getInstance() {
        static ConfigLoader instance;
        return instance;
    }
    std::vector<std::string> load();

    // remove copy constructor
    ConfigLoader(ConfigLoader const&) = delete;
    void operator=(ConfigLoader const&) = delete;

private:
    std::vector<std::string> nss_;

    ConfigLoader();
    std::vector<std::string> parseConf(const std::string& filename);
};

class Client {
public:
    Client();
    Client(const std::string ns);
    int resolv(const std::string dname, const Type type = A,
               const bool recurse = true, const bool edns = true,
               const bool wout = true, const unsigned int ntrials = 1);
    int resolv(const std::string dname, const unsigned int port,
               const Type type = A, const bool recurse = true,
               const bool edns = true, const bool wout = true,
               const unsigned int ntrials = 1);
    std::shared_ptr<Answer> answer();
    std::vector<std::shared_ptr<Answer>> answers();

private:
    std::vector<std::string> nss_;
    std::vector<std::shared_ptr<Answer>> ans_;

    std::shared_ptr<Answer> parse(
        const unsigned char* ans, const size_t alen,
        const std::chrono::duration<double, std::milli> elapsed);

    int print(const std::shared_ptr<Answer> ans);
};
}  // namespace dns