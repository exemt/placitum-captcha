# Placitum captcha

English · [Русский](README.ru.md)

Placitum captcha: a gate that asks the client to prove it is a person when there is a reason to.

One image, two processes. The inspector on the bus decides `allow`, `redirect` or `deny`; the widget
service shows the challenge and gives the client a clearance cookie. They share a key, and that is
the only thing connecting them.

```
module ──► waf.req.captcha ──► captcha       ── allow | redirect | deny
                                  │
                                  ├── decision: profile, clearance cookie, buckets, neighbour requests
                                  └── buckets and roster in the internal Redis

client ──► /waf/captcha ──► captcha-http     ── widget, answer check, waf_clr cookie
```

## What it can do

- **Buckets by axis**: address, subnet, autonomous system, session. GCRA in the internal Redis, one
  writer for all instances and one sum for all of them.
- **Providers**: its own image challenge or external ones: Turnstile, reCAPTCHA, hCaptcha and
  SmartCaptcha. The profile chooses the provider, and a widget that fails to load gives way to the
  next one.
- **Inline form** (`gate.inline`): the widget page comes as the body of the deny answer, without a
  redirect. Useful behind a TLS terminator or on a non-standard port, where a redirect would send
  the browser to the wrong address.
- **Neighbour requests**: another inspector can tell captcha a fact about the client, and the
  captcha profile decides what to do with it.
- **Outcome writes** to active datasets: clearance, failure, ban, by address, subnet or system.
- **Observe mode**: the inspector always answers `allow` and records in the audit what it would have
  decided, so bucket thresholds can be tuned on live traffic.

## Profiles

The image ships four profiles in `profiles/`; the controller replaces them with generations from
the panel.

| Profile | What it does |
| --- | --- |
| `default` | the widget when buckets fill up or a neighbour asks for a challenge; own image challenge |
| `login` | the widget for every client without clearance, with a short clearance: sign-in and sign-up forms |
| `form` | like `login`, but the page comes in the body of the answer on the same URI |
| `observe` | always `allow`; the would-be decision goes to the audit |

A `_probe` profile is derived from `default` automatically for the health check. The widget page
is in English; the profile's `languages` list (`en`, `ru` by default) picks the page language
attribute from `Accept-Language`.

## Build and run

```sh
docker build -f deploy/Dockerfile -t placitum/captcha .
```

The inspector is the default command; the widget service is `captcha-http` from the same image.
What it needs, keys and settings are in [INSTALL.md](INSTALL.md).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
