ARG USERVER_IMAGE=ghcr.io/userver-framework/ubuntu-24.04-userver:latest
ARG MIGRATE_IMAGE=migrate/migrate:v4.19.1

FROM ${MIGRATE_IMAGE} AS migrate

COPY migrations /migrations

FROM ${USERVER_IMAGE} AS dev

WORKDIR /workspace

ENV CCACHE_DIR=/workspace/.ccache \
    USERVER_ENABLE_STACK_USAGE_MONITOR=0

CMD ["/bin/bash"]

FROM dev AS builder

COPY . /src
WORKDIR /src

RUN cmake --preset release -DUSERVER_PYTHON=/usr/bin/python3 \
    && cmake --build build-release -j"$(nproc)" --target smirkly-auth \
    && cmake --install build-release --component smirkly-auth --prefix /opt/smirkly-auth

FROM ${USERVER_IMAGE} AS prod

WORKDIR /app

ENV USERVER_ENABLE_STACK_USAGE_MONITOR=0

COPY --from=builder /opt/smirkly-auth/bin/smirkly-auth /app/bin/smirkly-auth
COPY --from=builder /opt/smirkly-auth/etc/smirkly-auth /app/configs

EXPOSE 8080

ENTRYPOINT ["/app/bin/smirkly-auth"]
CMD ["--config", "./configs/static_config.yaml"]
