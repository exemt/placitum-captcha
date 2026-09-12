# Установка

Два процесса из одного образа: инспектор подписан на шину и сети не слушает, сервис виджета —
обычный HTTP за узлом защиты. Обычно их поднимает фундамент установки (`placitum-core`).

## Что нужно рядом

| Компонент | Обязателен | Зачем |
| --- | --- | --- |
| NATS | да | очередь `waf.req.captcha`, аудит, журнал, поколение профилей |
| Redis: обменник | да, инспектору | заголовки запроса по локатору — без них не видна кука клиренса |
| Redis: внутренний | да, обоим | корзины, роастер: нонсы, картинки виджета, отказы, отзыв |
| Ключ подписи капчи | да, обоим | запечатывает куки `waf_clr` и `waf_cap`; один на оба процесса |
| Узел защиты | да, виджету | `/waf/captcha` проксируется на `captcha-http` за `location` с `waf off` |
| `geo` | при корзинах по подсети и системе | анонсы, номер и состав системы |
| `keeper` | при записи исходов в наборы | ведёт состав активных списков |
| Контроллер и ключ контура | при внешних провайдерах | секреты провайдеров открывает `captcha-http` ключом контура |

**Инспектор без обменника не стартует** — это осознанно: не видя куки клиренса, он уводил бы на
виджет даже тех, кто его уже прошёл.

## Ключ подписи

```sh
openssl rand -hex 32 > captcha.hmac
```

Один файл на оба процесса, монтируется секретом. Сменили ключ — все выданные куки клиренса
перестают приниматься, и клиенты проходят проверку заново.

## Переменные

### Общие

| Переменная | По умолчанию | Что |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | шина |
| `REDIS_URL`, `REDIS_INTERNAL_URL` | из `inspector.conf` | обменник и внутренний Redis |
| `WAF_CAPTCHA_NAME` | `captcha` | имя в реестре и в кадре присутствия |
| `WAF_CAPTCHA_KEY_FILE` | — | файл ключа подписи. Без него не стартуют оба |
| `WAF_CAPTCHA_PROFILES` | `/app/profiles` | профили из образа |
| `WAF_CAPTCHA_DATA` | `/var/lib/waf/captcha` | куда раскатка кладёт применённое поколение |
| `WAF_CAPTCHA_LOG` | `info` | уровень журнала |
| `WAF_CAPTCHA_STORE_TIMEOUT` | | потолок похода в Redis |

### Инспектор

| Переменная | По умолчанию | Что |
| --- | --- | --- |
| `WAF_CAPTCHA_SUBJECT` | `waf.req.captcha` | подписка |
| `WAF_CAPTCHA_VERSIONS` | `2` | версии схемы сообщения |
| `WAF_CAPTCHA_GEO_ADDR` | пусто | кодер гео; пусто — корзины по подсети и системе молчат |
| `WAF_CAPTCHA_GEO_TIMEOUT`, `WAF_CAPTCHA_GEO_NEG_MAX` | | ожидание кодера и отрицательный кэш |
| `WAF_CAPTCHA_HTTP_URL` | пусто | адрес `captcha-http` для `gate.inline`; пусто — такие профили отвечают редиректом |
| `WAF_CAPTCHA_WORKERS`, `WAF_CAPTCHA_QUEUE_DEPTH`, `WAF_CAPTCHA_QUEUE_FULL`, `WAF_CAPTCHA_CONF` | | очередь |

### Сервис виджета (`captcha-http`)

| Переменная | По умолчанию | Что |
| --- | --- | --- |
| `WAF_CAPTCHA_LISTEN` | `:8080` | адрес HTTP |
| `WAF_CAPTCHA_WEB` | `/app/web` | страница и скрипт виджета |
| `WAF_CAPTCHA_COOKIE_SECURE` | `on` | флаг `Secure` у куки; `off` — только для стенда без TLS |
| `WAF_CAPTCHA_REAL_IP_HEADER` | | заголовок с адресом клиента от узла |
| `WAF_CAPTCHA_CONTROLLER` | — | адрес контроллера: секреты внешних провайдеров |
| `WAF_CAPTCHA_SCOPE` | — | пространство, например `name:default` |
| `WAF_CAPTCHA_CONTOUR_KEY` | — | приватный ключ контура для открытия секретов провайдеров |

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

Одна копия `captcha-http`: узел резолвит имя один раз, и вторая копия за тем же именем
получала бы запросы, но не проверки.

## Проверка после запуска

```sh
# Инспектор: проба идёт тем же путём, что модуль, и ждёт redirect
docker exec <инспектор> captcha-probe --quiet --timeout 1s --expect redirect

# Виджет отвечает
curl -fsS http://captcha-http:8080/status
```

## Грабли

- **Разные ключи у двух процессов** — виджет выдаёт куку, которую инспектор не принимает, и
  клиент ходит по кругу между проверкой и редиректом.
- **`WAF_CAPTCHA_COOKIE_SECURE=off` вне стенда** — кука клиренса уходит по открытому каналу.
- **Корзины — во внутреннем Redis, не в обменнике.** Перепутанные адреса дают счёт, который у
  каждого экземпляра свой, и порог не срабатывает никогда.
