# Installation

English · [Русский](INSTALL.ru.md)

Two processes from one image: the inspector subscribes to the bus and does not listen on the
network, the widget service is a plain HTTP service behind the protection node. Usually
`placitum-core` installs them.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | the `waf.req.captcha` queue, audit, log, profile generations |
| Buffer Redis | yes, for the inspector | request headers by locator: without them the clearance cookie is invisible |
| Internal Redis | yes, for both | buckets and roster: nonces, widget images, failures, revocation |
| Captcha signing key | yes, for both | seals the `waf_clr` and `waf_cap` cookies; one key for both processes |
| Protection node | yes, for the widget | `/waf/captcha` is proxied to `captcha-http` |
| `geo` | for subnet and AS buckets | announcements, AS number and composition |
| `keeper` | for outcome writes to datasets | owns active dataset contents |
| Controller and installation key | for external providers | `captcha-http` opens provider secrets with the installation key |

**The inspector does not start without the buffer.** Without the clearance cookie it would send
clients that already passed the challenge to the widget again.

## Signing key

```sh
openssl rand -hex 32 > captcha.hmac
```

One file for both processes, mounted as a secret. Changing the key invalidates every clearance
cookie, and clients pass the challenge again.

## Settings

### Common

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus |
| `REDIS_URL`, `REDIS_INTERNAL_URL` | from `inspector.conf` | buffer and internal Redis |
| `WAF_CAPTCHA_NAME` | `captcha` | name in the registry and the presence frame |
| `WAF_CAPTCHA_KEY_FILE` | — | signing key file; neither process starts without it |
| `WAF_CAPTCHA_PROFILES` | `./profiles`; `/app/profiles` in the image | profiles |
| `WAF_CAPTCHA_DATA` | empty; `/var/lib/waf/captcha` in the image | where rollout puts the applied generation |
| `WAF_CAPTCHA_LOG` | `info` | log level |
| `WAF_CAPTCHA_STORE_TIMEOUT` | `150ms` | Redis request limit |

### Inspector

| Variable | Default | Purpose |
| --- | --- | --- |
| `WAF_CAPTCHA_SUBJECT` | `waf.req.captcha` | subscription |
| `WAF_CAPTCHA_VERSIONS` | `2` | accepted message schema versions |
| `WAF_CAPTCHA_GEO_ADDR` | empty | geo coder; empty keeps subnet and AS buckets silent |
| `WAF_CAPTCHA_GEO_TIMEOUT`, `WAF_CAPTCHA_GEO_NEG_MAX` | `500ms`, `0` | coder wait and negative cache |
| `WAF_CAPTCHA_HTTP_URL` | empty | `captcha-http` address for `gate.inline`; empty makes such profiles redirect |
| `WAF_CAPTCHA_WORKERS`, `WAF_CAPTCHA_QUEUE_DEPTH`, `WAF_CAPTCHA_QUEUE_FULL`, `WAF_CAPTCHA_CONF` | CPUs, `inspector.conf` | queue |

### Widget service (`captcha-http`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `WAF_CAPTCHA_LISTEN` | `:8080` | HTTP address |
| `WAF_CAPTCHA_WEB` | `./web`; `/app/web` in the image | widget page and script |
| `WAF_CAPTCHA_COOKIE_SECURE` | `on` | `Secure` flag on cookies; `off` only while the node serves plain HTTP |
| `WAF_CAPTCHA_REAL_IP_HEADER` | `X-Forwarded-For` | client address header; the last value is used, the one the node appended |
| `WAF_CAPTCHA_CONTROLLER` | — | controller address: external provider secrets |
| `WAF_CAPTCHA_SCOPE` | — | space, for example `name:default` |
| `WAF_CAPTCHA_CONTOUR_KEY` | — | private installation key that opens provider secrets |

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

Run one copy of `captcha-http`: the node resolves the name once, and a second copy behind the same
name would receive requests but not challenges.

## Checking

```sh
# Inspector: the probe takes the module's path and expects a redirect
docker exec <inspector> captcha-probe --quiet --timeout 1s --expect redirect

# Widget service
curl -fsS http://captcha-http:8080/status
```

## Pitfalls

- **Different keys in the two processes**: the widget issues a cookie the inspector does not
  accept, and the client loops between the challenge and the redirect.
- **`WAF_CAPTCHA_COOKIE_SECURE=off` over TLS**: the clearance cookie may leak over plain HTTP.
- **Buckets live in the internal Redis, not in the buffer.** Mixed-up addresses give every
  instance its own count, and the threshold never fires.
