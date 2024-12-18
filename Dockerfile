FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libpq5

ARG TARGETARCH

ADD rsauth-server-$TARGETARCH /rust/bin/rsauth-server

EXPOSE 3001

ENTRYPOINT /rust/bin/rsauth-server
