FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/captcha ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/captcha-http ./cmd/http && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/captcha-probe ./cmd/probe

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/captcha" \
      org.opencontainers.image.description="Placitum captcha: challenge inspector and widget service in one image" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-captcha" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/captcha /out/captcha-http /out/captcha-probe /usr/local/bin/
COPY profiles ./profiles
COPY web ./web
COPY inspector.conf ./inspector.conf

RUN adduser -D -H -u 10002 captcha && \
    mkdir -p /var/lib/waf/captcha && \
    chown -R captcha:captcha /app /var/lib/waf
USER captcha

ENV NATS_URL=nats://nats:4222 \
    WAF_CAPTCHA_SUBJECT=waf.req.captcha \
    WAF_CAPTCHA_NAME=captcha \
    WAF_CAPTCHA_PROFILES=/app/profiles \
    WAF_CAPTCHA_DATA=/var/lib/waf/captcha \
    WAF_CAPTCHA_WEB=/app/web \
    WAF_CAPTCHA_LISTEN=:8080 \
    WAF_CAPTCHA_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["captcha-probe", "--quiet", "--timeout", "1s", "--expect", "redirect"]

CMD ["captcha"]
