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
	mkdir -p /rootfs/usr/bin
	cp target/${ARCH}-unknown-linux-musl/release/locksmithd /rootfs/usr/bin/locksmithd
EOF

FROM stagex/core-filesystem AS package
COPY --from=build /rootfs/ /
ADD .caution/secrets/bundle.json /etc/caution/
ADD .caution/secrets/API_KEY.asc /etc/caution/
ADD <<EOF /etc/environment
RUST_LOG=debug
EOF
ENTRYPOINT ["/usr/bin/locksmithd"]
