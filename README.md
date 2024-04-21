# DNS Benchmark

support A/AAAA/PTR/CNAME/MX/TXT record only.
*No IPv6 support for PTR record.

TCP fallback and EDNS0 are not supported.

## Build

```sh
cmake -B$(pwd)/build .
# if build with DEBUG mode
cmake -B$(pwd)/build -DCMAKE_BUILD_TYPE=Debug .

cmake --build $(pwd)/build
```

## Build with Docker

```sh
docker build -t dns-benchmark-build .
docker run --rm -t -v .:/build --name build dns-benchmark-build \
  /bin/sh -c 'cmake -B$(pwd)/build . && cmake --build $(pwd)/build'
```

## Usage

```sh
dns-benchmark -h
# example
dns-benchmark www.google.com
```