# Builds the static binaries and puts them in an empty image.
#
#   docker build -t malmal .
#   docker run --rm -p 127.0.0.1:8080:8080 malmal
#   docker run --rm -v "$PWD:/files:ro" --entrypoint /usr/local/bin/malmal malmal scan /files/upload.pdf

FROM rust:1-alpine AS build
# `ring`, for TLS in the daemon, compiles C against the musl headers.
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p malmal-cli

FROM scratch
COPY --from=build /src/target/release/malmal /src/target/release/malmald /usr/local/bin/
# The daemon needs no privileges and no files.
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/malmald"]
# Without --token-file or --tls-client-ca anyone who reaches the port can use
# the daemon: publish it to the upload service only.
CMD ["--http", "0.0.0.0:8080"]
