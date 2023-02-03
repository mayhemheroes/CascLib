# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake make

## Add source code to the build stage.
ADD . /src
WORKDIR /src

## Build
RUN mkdir build && cd build && \
    cmake .. -DCASC_MAYHEM=On && \
    make -j$(nproc)

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /src/build/mayhem/fuzz_casc /fuzz_casc
COPY --from=builder /src/build/libcasc.so.1 /usr/lib

## Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_casc
