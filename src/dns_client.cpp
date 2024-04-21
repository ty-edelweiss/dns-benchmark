#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <netinet/in.h>
#include <resolv.h>

#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <format>

#include "./dns_client.hpp"
#include "./utils.hpp"

namespace dns {

ConfigLoader::ConfigLoader() : nss_(parseConf(DNS_RESOLVFILE)) {}

std::vector<std::string> ConfigLoader::load() { return nss_; }

std::vector<std::string> ConfigLoader::parseConf(const std::string& filename) {
    std::ifstream ifs(filename);
    if (!ifs) {
        std::cerr << "failed to open " << filename << std::endl;
        exit(1);
    }

    std::vector<std::string> servers;

    std::string line;
    while (std::getline(ifs, line)) {
        line = util::trim(line);
        if (line.empty() || line.front() == '#') {
            continue;
        }
        if (line.find("nameserver") == 0) {
            auto iter = std::find_if(std::next(line.begin(), 10), line.end(),
                                     [](char c) { return !std::isspace(c); });
            servers.push_back(line.substr(std::distance(line.begin(), iter)));
        }
    }

#ifndef NDEBUG
    for (int i = 0; i < servers.size(); i++) {
        std::string index = std::to_string(i + 1);
        util::debug("nameserver " + index, " : ", servers[i]);
    }
#endif

    return servers;
}

Client::Client() {
    ConfigLoader& confLoader = ConfigLoader::getInstance();
    nss_ = confLoader.load();
}

Client::Client(const std::string ns) { nss_.push_back(ns); }

int Client::resolv(const std::string dname, const Type type, const bool wout,
                   const unsigned int ntrials) {
    return resolv(dname, DNS_PORT, type, wout, ntrials);
}

// support UDP only.
int Client::resolv(const std::string dname, const unsigned int port,
                   const Type type, const bool wout,
                   const unsigned int ntrials) {
    int sockfd;
    struct sockaddr_in addr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        std::cerr << "socket is invalid" << std::endl;
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    std::string ns = nss_.front();
    if (inet_pton(AF_INET, ns.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "nameserver address is invalid" << std::endl;
        shutdown(sockfd, SHUT_RDWR);
        return 1;
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("error on connect()");
        shutdown(sockfd, SHUT_RDWR);
        return 1;
    }

    ns_type qtype;
    switch (type) {
        case AAAA:
            qtype = ns_t_aaaa;
            break;
        case PTR:
            qtype = ns_t_ptr;
            break;
        case CNAME:
            qtype = ns_t_cname;
            break;
        case MX:
            qtype = ns_t_mx;
            break;
        case TXT:
            qtype = ns_t_txt;
            break;
        case A:
        default:
            qtype = ns_t_a;
            break;
    }

    unsigned char query[DNS_BUFFER_SIZE];
    size_t qlen;
    if (qtype != ns_t_ptr) {
#ifndef NDEBUG
        util::debug("query => ", dname);
#endif
        qlen = res_mkquery(ns_o_query, dname.c_str(), ns_c_in, qtype, nullptr,
                           0, nullptr, query, sizeof(query));
    } else {
        // Only IPv4 is supported for PTR query.
        unsigned char tmp[INET_ADDRSTRLEN];
        if (inet_pton(AF_INET, dname.c_str(), tmp) <= 0) {
            std::cerr << "address is invalid" << std::endl;
            shutdown(sockfd, SHUT_RDWR);
            return 1;
        }
        std::string daddr = std::format("{:d}.{:d}.{:d}.{:d}.in-addr.arpa",
                                        tmp[3], tmp[2], tmp[1], tmp[0]);
#ifndef NDEBUG
        util::debug("query => ", daddr);
#endif
        qlen = res_mkquery(ns_o_query, daddr.c_str(), ns_c_in, qtype, nullptr,
                           0, nullptr, query, sizeof(query));
    }

    ans_.clear();

    for (int i = 0; i < ntrials; i++) {
        std::chrono::system_clock::time_point start, end;

        if (send(sockfd, query, qlen, 0) < 0) {
            perror("error on send()");
            continue;
        }

        start = std::chrono::system_clock::now();

        unsigned char buffer[DNS_BUFFER_SIZE];
        ssize_t length;
        if ((length = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) < 0) {
            perror("error on recv()");
            continue;
        };

        end = std::chrono::system_clock::now();

        std::shared_ptr<Answer> ans = parse(buffer, length, end - start);

        ans_.push_back(ans);

        if (wout && print(ans)) {
            std::cerr << "failed to print DNS answer" << std::endl;
            continue;
        }
    }

    shutdown(sockfd, SHUT_RDWR);

    return 0;
};

std::shared_ptr<Answer> Client::answer() {
    return !ans_.empty() ? ans_.front() : nullptr;
}

std::vector<std::shared_ptr<Answer>> Client::answers() { return ans_; }

std::shared_ptr<Answer> Client::parse(
    const unsigned char* ans, const size_t alen,
    const std::chrono::duration<double, std::milli> elapsed) {
    std::shared_ptr<Answer> answer = std::make_shared<Answer>(Answer{
        /* status */ Answer::Error, /* authority */ false, /* count */ 1,
        /* records */ {}, /* metrics */ {/* elapsed */ elapsed, /* total */}});

    answer->metrics.elapsed = elapsed;
    answer->metrics.total = alen;

    HEADER* hp = (HEADER*)ans;

    answer->authority = (bool)hp->aa;

    if (hp->rcode) {
        std::cerr << "failed to get answer: RCODE[" << hp->rcode << "]"
                  << std::endl;
        return answer;
    } else if (hp->tc) {
        std::cerr << "failed to get answer because of the size" << std::endl;
        return answer;
    }

    // parse DNS answer.
    ns_msg msg;
    if (ns_initparse(ans, alen, &msg)) {
        std::cerr << "failed to parse message" << std::endl;
        return answer;
    }

    answer->count = ns_msg_count(msg, ns_s_an);

    // parse DNS record.
    ns_rr rr;
    for (int i = 0; i < answer->count; i++) {
        int n;
        char addr[INET_ADDRSTRLEN];
        char addr6[INET6_ADDRSTRLEN];
        char dname[MAXDNAME];

        if (ns_parserr(&msg, ns_s_an, i, &rr)) {
            std::cerr << "failed to parse record #" << i << std::endl;
            continue;
        }

        Answer::Record record;

        record.name = ns_rr_name(rr);
        record.size = ns_rr_rdlen(rr);

        switch (ns_rr_type(rr)) {
            case /* A record */ ns_t_a:
                inet_ntop(AF_INET, ns_rr_rdata(rr), addr, sizeof(addr));
                record.type = A;
                record.data = addr;
                break;
            case /* AAAA record */ ns_t_aaaa:
                inet_ntop(AF_INET6, ns_rr_rdata(rr), addr6, sizeof(addr6));
                record.type = AAAA;
                record.data = addr6;
                break;
            case /* PTR record */ ns_t_ptr:
                record.type = PTR;
                if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
                                       ns_rr_rdata(rr), dname,
                                       sizeof(dname)) < 0) {
                    std::cerr << "failed to uncompress record #" << i
                              << std::endl;
                    continue;
                }
                record.data = dname;
                break;
            case /* CNAME record */ ns_t_cname:
                record.type = CNAME;
                if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
                                       ns_rr_rdata(rr), dname,
                                       sizeof(dname)) < 0) {
                    std::cerr << "failed to uncompress record #" << i
                              << std::endl;
                    continue;
                }
                record.data = dname;
                break;
            case /* MX record */ ns_t_mx:
                record.type = MX;
                n = ns_get16(ns_rr_rdata(rr));
                if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
                                       ns_rr_rdata(rr) + 2, dname,
                                       sizeof(dname)) < 0) {
                    std::cerr << "failed to uncompress record #" << i
                              << std::endl;
                    continue;
                }
                record.attr.push_back(n);
                record.data = dname;
                break;
            case /* TXT record */ ns_t_txt:
                record.type = TXT;
                n = *ns_rr_rdata(rr);
                record.data = std::string(
                    reinterpret_cast<const char*>(ns_rr_rdata(rr) + 1), n);
                break;
            default:
#ifndef NDEBUG
                util::debug("DNS record #", i, " skipped");
#endif
                break;
        }

        answer->records.push_back(record);
    }

    answer->status = Answer::Ok;

    return answer;
}

int Client::print(const std::shared_ptr<Answer> ans) {
    if (ans->status == Answer::Error) {
        return 0;
    }

    if (!ans->authority) {
        std::cout << "Non-Authoritative Answer:" << std::endl;
    }

    for (Answer::Record& record : ans->records) {
        switch (record.type) {
            case A:
            case AAAA:
                std::cout << "Name:\t" << record.name << std::endl;
                std::cout << "Address: " << record.data << std::endl;
                break;
            case PTR:
                std::cout << "Address: " << record.name << std::endl;
                std::cout << "Name:\t" << record.data << std::endl;
                break;
            case CNAME:
                std::cout << "Name:\t" << record.name;
                std::cout << " <CNAME>" << std::endl;
                break;
            case MX:
                std::cout << "Exchange:\t" << record.data;
                std::cout << " <" << record.attr[0] << ">" << std::endl;
                break;
            case TXT:
                std::cout << "Text:\t" << record.data << std::endl;
                break;
            default:
                break;
        }
    }

    std::cout << "(";
    std::cout << std::fixed << std::setprecision(3)
              << ans->metrics.elapsed.count() << "ms";
    std::cout << ")" << std::endl;

    return 0;
}
}  // namespace dns