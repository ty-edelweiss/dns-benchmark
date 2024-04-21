#include <algorithm>

#include "./utils.hpp"

namespace util {

std::string uppercase(const std::string &str) {
    std::string out = str;
    std::transform(str.begin(), str.end(), out.begin(),
                   [](char c) { return toupper(c); });
    return out;
}

std::string lowercase(const std::string &str) {
    std::string out = str;
    std::transform(str.begin(), str.end(), out.begin(),
                   [](char c) { return tolower(c); });
    return out;
}

std::string trim(const std::string &str) {
    return std::string(
        std::find_if(str.begin(), str.end(), [](int c) { return !std::isspace(c); }),
        std::find_if(str.rbegin(), str.rend(), [](int c) { return !std::isspace(c); }).base()
    );
}

std::string ltrim(const std::string &str) {
    return std::string(
        std::find_if(str.begin(), str.end(), [](int c) { return !std::isspace(c); }),
        str.end()
    );
}

std::string rtrim(const std::string &str) {
    return std::string(
        str.begin(),
        std::find_if(str.rbegin(), str.rend(), [](int c) { return !std::isspace(c); }).base()
    );
}
}