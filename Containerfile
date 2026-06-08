FROM stagex/pallet-rust@sha256:4062550919db682ebaeea07661551b5b89b3921e3f3a2b0bc665ddea7f6af1ca AS build
COPY --from=stagex/core-openssl@sha256:4ecf4f42ad958a25d4622b246aacdbccd523aacbb8ce036f387d39e8a17b9840 . /
COPY --from=stagex/user-nettle@sha256:bdb4bf7adaad5ae08ebea7fa1d107e7eea3ed310e796f9350820ea053f5061a1 . /
COPY --from=stagex/pallet-clang@sha256:4460884be2fda90d933af1baff87c7d12756e79de48733cab5d6f65045bddc50 . /
COPY --from=stagex/core-gmp@sha256:b69f72317a6a674e2b88c074bce0e7d11fc7b9df2f3585d43838e49ee4e4c16a . /
COPY --from=stagex/user-pcsc-lite@sha256:baf390270d5a5e9a2daa3a5a99f346557f2111d801cd8f35050e36360ab3a7f8 . /
COPY . .
ENV RUST_BACKTRACE=1
RUN <<-EOF
	ARCH="$(uname -m)"
	cargo fetch \
		--locked \
		--target "${ARCH}-unknown-linux-musl"
EOF
RUN --network=none <<-EOF
	ARCH="$(uname -m)"
	RUSTFLAGS="-C target-feature=+crt-static" \
	cargo build \
		--frozen \
		--release \
		--target "${ARCH}-unknown-linux-musl" \
		--bin keymaker
EOF
RUN printf 'KEYFORK_OPENPGP_EXPIRE=42y\n' > /etc/environment
FROM scratch AS runtime
COPY --from=build /etc/environment /etc/environment
COPY --from=build /target/*-unknown-linux-musl/release/keymaker /
