# Контекст сборки -- корень репозитория.
#
#     docker build -f deploy/Dockerfile -t placitum/captcha .
#     docker buildx build -f deploy/Dockerfile -t placitum/captcha \
#         "https://github.com/exemt/placitum-captcha.git#develop"
#
# Один образ, два контейнера: инспектор запускает `captcha`, сервис виджета --
# `captcha-http`. Ключ у них общий, и это единственное, чем они связаны.

FROM golang:1.25-alpine AS build

WORKDIR /src

# Прокси модулей -- аргументом: в изолированном контуре подставляют своё зеркало.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

# Зависимости отдельным слоем; download, а не tidy: сборка обязана повторять
# go.mod, а не переписывать его.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
# Профили из образа: их разбирает тест internal/config -- без каталога образ
# собирался бы, а опечатка в поставочном профиле ловилась бы на ноде.
COPY profiles ./profiles

# Тесты в сборке: образ с красными тестами ставить нельзя. Сверка словаря
# действий со схемой провода здесь пропускается сама: схема лежит в платформе,
# а не в компоненте.
RUN go test ./...

RUN go build -trimpath -ldflags="-s -w" -o /out/captcha ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w" -o /out/captcha-http ./cmd/http && \
    go build -trimpath -ldflags="-s -w" -o /out/captcha-probe ./cmd/probe

FROM alpine:3.22

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает.
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

# Каталог применённого поколения создаётся заранее и отдаётся процессу: том
# монтируется поверх него и наследует владельца, иначе первая же раскатка
# упирается в permission denied и остаётся на bootstrap-профилях.
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

# Проба идёт тем же путём, что модуль: публикует инспекцию и ждёт вердикт.
# Профиль _probe отвечает redirect без cookie и счёта; живость доказывает сам
# факт ответа, ожидание -- политику. Для captcha-http установка переопределяет
# проверку на HTTP.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["captcha-probe", "--quiet", "--timeout", "1s", "--expect", "redirect"]

CMD ["captcha"]
