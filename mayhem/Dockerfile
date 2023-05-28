FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang libmicrohttpd-dev automake pkg-config libtool

COPY . /repo
WORKDIR /repo
RUN ./bootstrap
WORKDIR /repo/build
RUN ../configure --prefix=/install
RUN make -j8
RUN make install

RUN clang++ /repo/mayhem/fuzz_to_lower_copy.cpp  -fsanitize=fuzzer,address -std=c++17 -I /repo/src/ /install/lib/libhttpserver.a -o /fuzz_to_lower_copy

FROM ubuntu:22.04 as package

COPY --from=builder /fuzz /fuzz_to_lower_copy
