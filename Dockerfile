FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libpq5

ADD rsauth-server /rust/bin/rsauth-server

EXPOSE 3001

# I'm all for minimal, but having sh is useful
COPY --from=busybox /bin/sh /bin/sh

ENTRYPOINT /rust/bin/rsauth-server
