FROM stagex/pallet-rust AS pallet-rust
FROM stagex/core-gmp AS core-gmp
FROM stagex/user-nettle AS user-nettle
FROM stagex/user-pcsc-lite AS user-pcsc-lite

FROM stagex/pallet-rust AS build
COPY --from=core-gmp . /
COPY --from=user-nettle . /
COPY --from=user-pcsc-lite . /

COPY . /locksmith
WORKDIR /locksmith
RUN --mount=type=cache,target=/root/.cargo cargo fetch
ENV RUSTFLAGS="-C codegen-units=1 -C target-feature=+crt-static"
RUN --network=none \
	--mount=type=cache,target=/root/.cargo \
	--mount=type=cache,target=/locksmith/target \
	<<-EOF
	ARCH="$(uname -m)"
	cargo build \
		--frozen \
		--release \
		--target "${ARCH}-unknown-linux-musl" \
		--bin locksmithd
	cargo build \
		--frozen \
		--release \
		--target "${ARCH}-unknown-linux-musl" \
		--bin locksmith-oneshot
	mkdir -p /rootfs/usr/bin
	cp target/${ARCH}-unknown-linux-musl/release/locksmithd /rootfs/usr/bin
	cp target/${ARCH}-unknown-linux-musl/release/locksmith-oneshot /rootfs/usr/bin
	cp test.sh /rootfs/usr/bin/test-locksmith
EOF

FROM stagex/core-filesystem AS package
COPY --from=build /rootfs/ /
ADD bundle-2-of-4.json /etc/caution/bundle.json
ADD secrets /etc/caution/secrets
# TODO: where put keyforkd?
ADD <<EOF /etc/environment
RUST_LOG=debug
KEYFORKD_SOCKET_PATH=/keyforkd.sock
EOF
ENTRYPOINT ["/usr/bin/locksmithd"]
