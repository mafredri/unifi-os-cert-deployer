# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS uploader-build

WORKDIR /src
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags="-s -w" -o /out/unifi-cert-upload ./cmd/unifi-cert-upload

FROM goacme/lego:v5.5.1
COPY --from=uploader-build /out/unifi-cert-upload /usr/local/bin/unifi-cert-upload
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN /lego --version \
	&& chmod 0755 /usr/local/bin/unifi-cert-upload /usr/local/bin/docker-entrypoint.sh

ENV LEGO_PATH=/data \
	LEGO_DEPLOY_HOOK=/usr/local/bin/unifi-cert-upload \
	LEGO_NO_BUNDLE=true
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
