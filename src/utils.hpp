#pragma once

#include <iostream>
#include <sstream>
#include <string>
#include <thread>

namespace util {

template<typename... Args>
void print(Args... args) {
    std::stringstream ss;
    (ss << ... << args) << std::endl;
    std::cout << ss.str();
}

template<typename... Args>
void debug(Args... args) {
    print("[DEBUG] : ", args...);
}

std::string uppercase(const std::string &str);
std::string lowercase(const std::string &str);

std::string trim(const std::string &str);
std::string ltrim(const std::string &str);
std::string rtrim(const std::string &str);
}