FROM stagex/pallet-rust@sha256:4e2d4273a1d5c6d62660968302791f3cf550c3d12629e66314956ff46c97fc0e AS pallet-rust
FROM stagex/core-gmp@sha256:2ec32c41b02d95e56fae567be0df7fdea89a579f99073a6f80976a9916aac51b AS core-gmp
FROM stagex/user-nettle@sha256:2236c14e00e7d689a7d1c5c76c697895dfaba5b86b0f95f68a83a51362d54b57 AS user-nettle
FROM stagex/user-pcsc-lite@sha256:3dd0d1621383b47d28919178fc740fe102c334111545d4d49b1098a84bc1612e AS user-pcsc-lite

FROM pallet-rust AS build
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
	# cp target/${ARCH}-unknown-linux-musl/release/locksmith-oneshot /rootfs/usr/bin
	cp test.sh /rootfs/usr/bin/test-locksmith
EOF

FROM stagex/core-filesystem@sha256:da28831927652291b0fa573092fd41c8c96ca181ea224df7bff40e1833c3db13 AS package
COPY --from=build /rootfs/ /
ADD bundle-2-of-4.json /etc/caution/bundle.json
ADD secrets /etc/caution/secrets
# TODO: where put keyforkd?
ADD <<EOF /etc/environment
RUST_LOG=debug
KEYFORKD_SOCKET_PATH=/keyforkd.sock
EOF
ENTRYPOINT ["/usr/bin/locksmithd"]
