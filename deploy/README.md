# deploy

Контракт — [docs/inspectors/captcha/deploy](../../docs/inspectors/captcha/deploy/README.md).
В compose сервисов ещё нет.

```sh
docker build -f deploy/Dockerfile -t waf-captcha .
```

Тот же тег дважды: `inspector-captcha` и `captcha-http`. Секрет —
`waf_captcha_hmac`, не ключ челленджа.
