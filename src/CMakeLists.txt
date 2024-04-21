add_executable(dns-benchmark main.cpp utils.cpp dns_client.cpp dns_tester.cpp)

configure_file(config.h.in config.h)

find_package(Boost REQUIRED program_options)

target_link_options(dns-benchmark PRIVATE "LINKER:-lresolv")
target_include_directories(dns-benchmark PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${Boost_INCLUDE_DIR})
target_link_libraries(dns-benchmark ${Boost_LIBRARIES})