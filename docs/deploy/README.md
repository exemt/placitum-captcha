# Два контейнера капчи

Тот же паттерн, что у челленджа (`docs/inspectors/challenge/deploy/README.md`): один
образ, две команды, один secret на пару, контейнеры друг друга не вызывают.
Фрагмента в `docker-compose.yml` ещё нет.

```
inspectors/captcha/  →  waf-captcha:<sha>
                          ├── inspector-captcha
                          └── captcha-http
```

Отличия от JS-семьи:

| | Челлендж | Капча |
| --- | --- | --- |
| Тег | `waf-challenge` | `waf-captcha` |
| Subject | `waf.req.chal` | `waf.req.captcha` |
| Secret | `waf_challenge_hmac` | `waf_captcha_hmac` |
| Prefix Redis | `chal:` | `cap:` |
| HTTP location | `/waf/js`, `/waf/collect` | `/waf/captcha` |
| Пульс HTTP | `WAF_STATUS.service.challenge-http.<id>` | `WAF_STATUS.service.captcha-http.<id>` |
| Проба инспектора | ждать `redirect` без cookie | см. вопрос пробы в README: при `default` без счёта будет `allow` |

Секреты **разные файлы**. Один `gen.mjs` может выписать оба, но смонтировать
капче ключ челленджа нельзя: тогда JS, узнав один секрет, выпишет `waf_clr`.

`nginx` ждёт `healthy` обе пары, если оба модуля на стенде. Убрать капчу с
маршрута — убрать `captcha` из `waf_inspect`. Мёртвый
провайдер виджета не должен ронять `inspector-captcha`: healthcheck HTTP
проверяет ключ и слушает, не round-trip к Turnstile.

Стендовый `try_files /waf/captcha.html` уходит в
`proxy_pass http://captcha_http`, когда образ появится.
