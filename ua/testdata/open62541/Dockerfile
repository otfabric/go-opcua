# SPDX-License-Identifier: MIT
#
# Throwaway image used to (re)generate ../open62541_corpus.json. See README.md.
#   docker build -t go-opcua-uacodec ua/testdata/open62541
FROM debian:bookworm-slim AS build
ARG OPEN62541_COMMIT=v1.5.9
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates cmake git python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${OPEN62541_COMMIT}" https://github.com/open62541/open62541 \
    && cd open62541 && git submodule update --init --depth 1
WORKDIR /src/open62541/build
# JSON (the 1.05 form, not UA_ENABLE_JSON_ENCODING_LEGACY) and XML encodings
# are ON by default in v1.5.9. Build with
#   --build-arg OPEN62541_CMAKE_ARGS=-DUA_ENABLE_JSON_ENCODING_LEGACY=ON
# for the helper that speaks the OPC UA 1.04 JSON encoding instead.
ARG OPEN62541_CMAKE_ARGS=""
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
      -DUA_MULTITHREADING=0 -DUA_BUILD_EXAMPLES=OFF -DUA_BUILD_UNIT_TESTS=OFF \
      -DUA_ENABLE_ENCRYPTION=OFF -DCMAKE_INSTALL_PREFIX=/opt/ua ${OPEN62541_CMAKE_ARGS} \
    && cmake --build . -- -j"$(nproc)" && cmake --install .
COPY uacodec.c /src/uacodec.c
RUN cc -O2 -o /uacodec /src/uacodec.c -I/opt/ua/include -L/opt/ua/lib -lopen62541 -lm

FROM debian:bookworm-slim
COPY --from=build /uacodec /usr/local/bin/uacodec
ENTRYPOINT ["/usr/local/bin/uacodec"]
