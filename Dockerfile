FROM gcc:13

# only C compiler is linked with alternatives.
# https://github.com/docker-library/gcc/blob/master/13/Dockerfile#L156
RUN update-alternatives --install /usr/bin/c++ c++ /usr/local/bin/g++ 999 \
  && update-alternatives --install /usr/bin/gfortran gfortran /usr/local/bin/gfortran 999

RUN apt update && apt install -y \
  cmake \
  libboost-all-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

CMD [ "cmake", "-version" ]