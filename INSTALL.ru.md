# Установка

[English](INSTALL.md) · Русский

Два процесса из одного образа: инспектор подписан на шину и сети не слушает, сервис виджета —
обычный HTTP за узлом защиты. Обычно их ставит `placitum-core`.

## Что нужно рядом

| Компонент | Обязателен | Зачем |
| --- | --- | --- |
| NATS | да | очередь `waf.req.captcha`, аудит, журнал, поколение профилей |
| Redis: буфер | да, инспектору | заголовки запроса по локатору — без них не видна кука пропуска |
| Redis: внутренний | да, обоим | бакеты, реестр: нонсы, картинки виджета, блокировки, отзыв |
| Ключ подписи капчи | да, обоим | запечатывает куки `waf_clr` и `waf_cap`; один на оба процесса |
| Узел защиты | да, виджету | `/waf/captcha` проксируется на `captcha-http` |
| `geo` | при бакетах по подсети и системе | анонсы, номер и состав системы |
| `keeper` | при записи исходов в наборы | ведёт состав активных списков |
| Контроллер и ключ установки | при внешних провайдерах | секреты провайдеров открывает `captcha-http` ключом установки |

**Инспектор без буфера не стартует.** Не видя куки пропуска, он уводил бы на виджет даже тех,
кто его уже прошёл.

## Ключ подписи

```sh
openssl rand -hex 32 > captcha.hmac
```

Один файл на оба процесса, монтируется секретом. Сменили ключ — все выданные куки пропуска
перестают приниматься, и клиенты проходят проверку заново.

## Настройки

### Общие

| Переменная | По умолчанию | Что задаёт |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | шина |
| `REDIS_URL`, `REDIS_INTERNAL_URL` | из `inspector.conf` | буфер и внутренний Redis |
| `WAF_CAPTCHA_NAME` | `captcha` | имя в реестре и в кадре присутствия |
| `WAF_CAPTCHA_KEY_FILE` | — | файл ключа подписи; без него не стартуют оба |
| `WAF_CAPTCHA_PROFILES` | `./profiles`; в образе `/app/profiles` | профили |
| `WAF_CAPTCHA_DATA` | пусто; в образе `/var/lib/waf/captcha` | куда раскатка кладёт применённое поколение |
| `WAF_CAPTCHA_LOG` | `info` | уровень журнала |
| `WAF_CAPTCHA_STORE_TIMEOUT` | `150ms` | потолок похода в Redis |

### Инспектор

| Переменная | По умолчанию | Что задаёт |
| --- | --- | --- |
| `WAF_CAPTCHA_SUBJECT` | `waf.req.captcha` | подписка |
| `WAF_CAPTCHA_VERSIONS` | `2` | версии схемы сообщения |
| `WAF_CAPTCHA_GEO_ADDR` | пусто | кодер гео; пусто — бакеты по подсети и системе молчат |
| `WAF_CAPTCHA_GEO_TIMEOUT`, `WAF_CAPTCHA_GEO_NEG_MAX` | `500ms`, `0` | ожидание кодера и отрицательный кэш |
| `WAF_CAPTCHA_HTTP_URL` | пусто | адрес `captcha-http` для `gate.inline`; пусто — такие профили отвечают редиректом |
| `WAF_CAPTCHA_WORKERS`, `WAF_CAPTCHA_QUEUE_DEPTH`, `WAF_CAPTCHA_QUEUE_FULL`, `WAF_CAPTCHA_CONF` | число ядер, `inspector.conf` | очередь |

### Сервис виджета (`captcha-http`)

| Переменная | По умолчанию | Что задаёт |
| --- | --- | --- |
| `WAF_CAPTCHA_LISTEN` | `:8080` | адрес HTTP |
| `WAF_CAPTCHA_WEB` | `./web`; в образе `/app/web` | страница и скрипт виджета |
| `WAF_CAPTCHA_COOKIE_SECURE` | `on` | флаг `Secure` у куки; `off` — только пока узел отвечает по HTTP |
| `WAF_CAPTCHA_REAL_IP_HEADER` | `X-Forwarded-For` | заголовок с адресом клиента; берётся последнее значение — его дописал узел |
| `WAF_CAPTCHA_CONTROLLER` | — | адрес контроллера: секреты внешних провайдеров |
| `WAF_CAPTCHA_SCOPE` | — | пространство, например `name:default` |
| `WAF_CAPTCHA_CONTOUR_KEY` | — | приватный ключ установки для открытия секретов провайдеров |

## Docker Compose

```yaml
services:
  inspector-captcha:
    image: placitum/captcha
    environment:
      NATS_URL: nats://nats:4222
      REDIS_URL: redis://redis:6379
      REDIS_INTERNAL_URL: redis://redis-internal:6379
      WAF_CAPTCHA_KEY_FILE: /run/secrets/waf_captcha_hmac
      WAF_CAPTCHA_GEO_ADDR: geo:50051
      WAF_CAPTCHA_HTTP_URL: http://captcha-http:8080
    secrets: [waf_captcha_hmac]

  captcha-http:
    image: placitum/captcha
    command: ["captcha-http"]
    environment:
      NATS_URL: nats://nats:4222
      REDIS_INTERNAL_URL: redis://redis-internal:6379
      WAF_CAPTCHA_KEY_FILE: /run/secrets/waf_captcha_hmac
      WAF_CAPTCHA_LISTEN: ":8080"
      WAF_CAPTCHA_CONTROLLER: http://controller:8080
      WAF_CAPTCHA_SCOPE: name:default
      WAF_CAPTCHA_CONTOUR_KEY: /run/secrets/waf_node_key
    secrets: [waf_captcha_hmac, waf_node_key]
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/status"]
```

Одна копия `captcha-http`: узел резолвит имя один раз, и вторая копия за тем же именем получала бы
запросы, но не проверки.

## Проверка

```sh
# Инспектор: проба идёт тем же путём, что модуль, и ждёт redirect
docker exec <инспектор> captcha-probe --quiet --timeout 1s --expect redirect

# Сервис виджета
curl -fsS http://captcha-http:8080/status
```

## Типичные ошибки

- **Разные ключи у двух процессов** — виджет выдаёт куку, которую инспектор не принимает, и клиент
  ходит по кругу между проверкой и редиректом.
- **`WAF_CAPTCHA_COOKIE_SECURE=off` при TLS** — кука пропуска может уйти по открытому каналу.
- **Корзины — во внутреннем Redis, не в буфере.** Перепутанные адреса дают счёт, который у
  каждого экземпляра свой, и порог не срабатывает никогда.
