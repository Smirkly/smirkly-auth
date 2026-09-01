ARG USERVER_IMAGE=ghcr.io/userver-framework/ubuntu-24.04-userver:v3.0@sha256:3477357e5d6b874d69676b38d084dc153097c9d7a85f09fb5b059427dcfee990
ARG MIGRATE_IMAGE=migrate/migrate:v4.19.1

FROM ${MIGRATE_IMAGE} AS migrate

COPY migrations /migrations

FROM ${USERVER_IMAGE} AS dev

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        curl \
        libfreetype6 \
        libxi6 \
        libxext6 \
        libxrender1 \
        libxtst6 \
        procps \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && usermod --login developer --home /home/developer --move-home ubuntu \
    && groupmod --new-name developer ubuntu \
    && rm -f /etc/sudoers.d/ubuntu \
    && printf 'developer ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/developer \
    && chmod 0440 /etc/sudoers.d/developer \
    && install -d -o developer -g developer \
        /workspace/build-debug \
        /workspace/build-release \
        /workspace/.ccache

WORKDIR /workspace

ENV HOME=/home/developer \
    CCACHE_DIR=/workspace/.ccache \
    CPM_SOURCE_CACHE=/workspace/.ccache/cpm \
    USERVER_ENABLE_STACK_USAGE_MONITOR=0

USER developer

CMD ["/bin/bash"]

FROM dev AS builder

USER root

COPY . /src
WORKDIR /src

RUN cmake --preset release -DSMIRKLY_AUTH_ENABLE_TESTSUITE=OFF -DSMIRKLY_AUTH_ENABLE_TEST_CONTROL=OFF -DSMIRKLY_AUTH_ENABLE_PUBLIC_PING=OFF \
    && cmake --build build-release -j"$(nproc)" --target smirkly-auth \
    && cmake --install build-release --component smirkly-auth --prefix /opt/smirkly-auth

FROM ${USERVER_IMAGE} AS prod

RUN groupadd --system --gid 10001 smirkly-auth \
    && useradd --system --uid 10001 --gid smirkly-auth \
        --home-dir /home/smirkly-auth --create-home smirkly-auth \
    && install -d -o smirkly-auth -g smirkly-auth \
        /app \
        /var/cache/smirkly-auth

WORKDIR /app

ENV HOME=/home/smirkly-auth \
    USERVER_ENABLE_STACK_USAGE_MONITOR=0

COPY --from=builder --chown=smirkly-auth:smirkly-auth /opt/smirkly-auth/bin/smirkly-auth /app/bin/smirkly-auth
COPY --from=builder --chown=smirkly-auth:smirkly-auth /opt/smirkly-auth/etc/smirkly-auth /app/configs

EXPOSE 8080

USER smirkly-auth

ENTRYPOINT ["/app/bin/smirkly-auth"]
CMD ["--config", "./configs/static_config.prod.yaml"]
