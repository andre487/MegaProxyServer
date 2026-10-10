# API персональных конфигов

Опциональный `services.config_api` разворачивается на отдельных Debian/Ubuntu-машинах
из того же inventory. Все экземпляры равноправны: каждый получает одинаковые маршруты,
хеши доступа и зашифрованные данные пользователей. HTTPS-прокси и его маскировка остаются
на своих хостах. Полный пример: [inventory.config-api.example.yml](../../inventory.config-api.example.yml).

```yaml
services:
  config_api:
    enabled: true
    endpoint: configs.example.com
    certificate: domain
    acme_email: admin@example.com
    port: 443
    path: /api/config
    backend_port: 18081
    interval_minutes: 60
```

Для публичного IPv4 или IPv6 укажите IP без скобок в `endpoint` и `certificate: ip-acme`.
Сервис требует доверенный сертификат, поддерживает TLS 1.2/1.3 и не допускает self-signed
режим. Закреплённый Certbot выпускает сертификат; таймер каждые 12 часов проверяет
продление и перезагружает nginx. Порт 80 нужен для ACME standalone, постоянного HTTP-сайта
на нём нет. Публичный и внутренний порты должны различаться; внутренний порт не открывается
в firewall. Путь задаётся буквально, без query string; `/robots.txt` зарезервирован.

Добавить хост можно через `./mega-proxy add-host`, выбрав **Configuration API**. Установить
и проверить конфигурацию:

При ручном добавлении задайте `admin.private_key_file`: если `admin.public_key` не указан,
он автоматически получается из приватного ключа через `ssh-keygen -y`.
Без `admin.bootstrap_user` подключение идёт сразу под `admin.user`; этот пользователь
должен уже иметь доступ по ключу и sudo. Без `admin.bootstrap_auth` используется ключ.
Для первого входа по паролю задайте `admin.bootstrap_user: root` и `admin.bootstrap_auth: password`.
Bootstrap проверяет нового администратора по ключу и sudo, затем запрещает SSH-вход root
и административный вход по паролю. Для нового сервера сначала выполните
`./mega-proxy bootstrap --limit ИМЯ_ХОСТА`, затем plan/apply/verify с тем же `--limit`.

```sh
./mega-proxy plan
./mega-proxy apply
./mega-proxy verify
```

При изменении общих паролей применяйте inventory ко всем затронутым прокси и API-хостам:
`--limit` обновляет только выбранные машины. `enabled: false` останавливает API и его
таймер, удаляет пакет пользовательских данных и публичный nginx listener.

## Запросы и доступ

`GET /api/config` принимает Basic Auth с UTF-8 логином и паролем из `users.https`.
Сервис проверяет пару через scrypt с индивидуальной случайной солью, после чего создаёт
MegaProxy JSON v8 непосредственно для запроса. Логин и пароль HTTPS-профилей берутся
из запроса, а не из сохранённого открытого конфига. Каждый пользователь получает свои
HTTPS-профили всех маршрутов inventory.

SSH-профили доступны только через явные привязки:

```yaml
users:
  https:
    - name: alice
      password: REPLACE_WITH_AT_LEAST_16_CHARACTERS
      ssh_users: [tun-alice]
```

Для этих аккаунтов выдаются прямые SSH-профили и все jump-пары между разными SSH-хостами.
Оба аккаунта в jump-профиле должны входить в привязки пользователя. SSH-пароли и приватные
ключи шифруются AES-256-GCM ключом, выведенным через scrypt из HTTPS-пароля с отдельной
солью. Шифротекст связан с пользователем через authenticated data; модификация или
перестановка зашифрованных данных приводит к отказу. На запросе расшифровка выполняется
в памяти. Исходные ключи читаются на управляющей машине из `generated_private_key`.
При смене HTTPS-пароля `apply` заново шифрует их из исходных файлов.

| Запрос | Ответ |
| --- | --- |
| GET правильного пути с верными реквизитами | 200, `application/json; charset=utf-8` |
| Такой же запрос с совпавшим If-None-Match | 304 после проверки доступа |
| GET `/robots.txt` без авторизации | 200, `User-agent: *` и `Disallow: /` |
| Неверный путь, query string, метод или реквизиты | 403 без WWW-Authenticate |

Все ответы содержат `X-Robots-Tag: noindex, nofollow, noarchive` и
`Cache-Control: private, no-store`. nginx не кеширует и не записывает ответы во временные
файлы. Access log выключен; API не журналирует пути, Authorization или тела конфигов.
Перегрузка и внутренние ошибки также возвращают 403. Перед Python-сервисом nginx
ограничивает запросы до 30 в минуту с burst 20 на IP; Python последовательно обрабатывает
запросы, ограничивая память scrypt. `/robots.txt` не расходует этот лимит.

## Контракт MegaProxyConfig

Используются [формат v8](https://github.com/andre487/MegaProxyConfig/blob/602c9c2a689afda6fc0a685435a1d3f82d404120/docs/configuration.md)
и [протокол доставки](https://github.com/andre487/MegaProxyConfig/blob/602c9c2a689afda6fc0a685435a1d3f82d404120/docs/subscription-protocol.md).
Схемы и LICENSE сохранены в `schemas/`; commit и SHA-256 зафиксированы в
[lock-файле](../../schemas/megaproxy-config.lock.json). Проверки работают без скачивания `main`.
Выбор 403 вместо стандартного 401 с Basic challenge сделан намеренно по политике этого API.

Ответ — полный снимок со стабильными ID, без дополнительной обёртки и перенаправлений.
ID генерируемого API-профиля зависит от логического хоста, маршрута и аккаунта;
смена отображаемого title или endpoint сохраняет ID.
Он содержит `subscription`: URL отвечающего экземпляра, остальные равноправные URL
в `fallbackUrls`, реквизиты из запроса, интервал и флаг включения. Максимум восемь
API-адресов соответствует ограничению протокола. Импорт такого ответа создаёт bootstrap
подписки. При обновлении клиент сохраняет локальный список источников и реквизиты,
как требует протокол. Порядок попыток задаёт клиент, серверного primary нет.

`X-MegaProxy-Client: browser_chromium` и `browser_firefox` выбирают HTTPS и совместимые
SOCKS5-профили; SSH/jump/MASQUE-профили и Android-поля в этот ответ не включаются.
Chromium не получает SOCKS5 с реквизитами; для Firefox проверяется лимит 255 UTF-8 байт.
Значения `android` и `android_megaproxy` выбирают Android-проекцию без SOCKS5, IPv6 endpoints
и browser-полей. Без заголовка или с неизвестным значением возвращается общий формат v8.
Заголовок клиента не расширяет права на SSH-аккаунты.

`X-MegaProxy-Version` — версия приложения клиента. ETag учитывает пользователя, выбранный
ответ, ID и версию клиента; `Vary` включает Authorization и оба клиентских заголовка.
Аутентификация выполняется до любой проверки ETag. Last-Modified не используется;
If-Modified-Since без ETag приводит к обычной выдаче полного снимка.

Персональный выбор профиля, пауза и расписание обновлений, rollback, уведомления и
сохранение профилей вне подписки выполняются клиентом согласно контракту. API не хранит
клиентские сессии и возвращает данные для этих алгоритмов, включая `activeProfileId`.

## Все документированные поля настроек

В `settings.client_config` задаются общие root-поля v8, в `users.https[].client_config` —
персональные изменения. Персональный объект заменяет одноимённое root-поле целиком.
TLS/JA3, SSH, DNS, маршрутизация Android и браузеров, failover, active/always-on IDs,
WebRTC, theme/language и подписки списков сохраняются в соответствующей проекции.

```yaml
settings:
  client_config:
    routing:
      bypassLocalNetworks: true
    browser:
      theme: system
      language: auto
      routing:
        enabled: true
        mode: domains
        strategy: lists
        subscriptions:
          domainSources: [youtube]
          siteSources: []
          autoUpdate: true
          throughProxy: false
    subscription:
      intervalMinutes: 60
      enabled: true
```

`client_config.profiles` добавляет дополнительные полностью описанные профили v8 со
стабильными ID. Это позволяет описать уже работающие HTTPS_JUMP, SOCKS5 и MASQUE endpoints,
не разворачивая новые транспорты этим проектом. Такие поля, включая дополнительные
реквизиты, входят в зашифрованный персональный payload, а не в открытые маршруты пакета.
Дополнительные SSH/SSH_JUMP-профили также требуют привязки всех указанных SSH-аккаунтов;
общие настройки не могут обойти эту проверку.

Для генерируемых профилей можно задать `services.https.client_profile` или
`services.ssh.client_profile`: например `tls`, `dns`, `routing`, `browser.bypass`,
`browser.knockHost` и `proxy.preferHttp3`. Endpoint, тип, реквизиты, ID и имя генерируемого
профиля этими полями не меняются. Первый настроенный knock-host маршрута добавляется
автоматически; явный `browser.knockHost` имеет приоритет. Browser tab-routing передаётся
без переинтерпретации: Chromium сообщает о несовместимости и применяет свой алгоритм.

`passwordsIncluded: false` исключает пароли из профилей, jump-узлов и bootstrap подписки;
`privateKeysIncluded: false` исключает SSH-ключи. Значения по умолчанию — true, поскольку
это персональная авторизованная выдача. `client_config.subscription` допускает только
`intervalMinutes`, `enabled` или null; URL и реквизиты формируются из inventory и запроса.
Null выдаёт явное удаление подписки для ручного импорта. `schema` и `version` фиксированы.

Пакет проверяется до установки: типы полей, уникальность и ссылки ID, совместимость проекций,
непустые снимки, максимум 1 000 профилей и 1 MiB ответа. Семантику JA3, MASQUE templates и
подключений дополнительно проверяют клиенты согласно контракту. CLI `export`/`configs`
сохраняют прежний общий экспорт; `client_config` относится к персональному API.

## Проверка и подготовка

```sh
./mega-proxy config-bundle --output .generated/config-api.json
curl --fail --user alice https://configs.example.com/api/config
```

curl запросит пароль, не помещая его в историю команды. `apply` самостоятельно собирает
пакет и доставляет его только API-хостам. Неизменившиеся данные сохраняют шифротекст и
права файлов; обновления записываются атомарно. Удаление аккаунта удаляет его запись доступа.

Локальный тест с настоящим nginx и временным доверенным тестовым сертификатом:

```sh
uv run python tests/integration/config_api.py --nginx /path/to/nginx
```

Он проверяет HTTPS, canonical v8, ETag после аутентификации, robots.txt, буквальное сравнение
путей и ответы 403/noindex. В рабочие API-пакеты не входят полный inventory, административные
ключи, исходные пути SSH-ключей или машинные пароли HTTPS-цепочек. Работающий API получает
пароль и расшифрованные SSH-секреты в памяти во время авторизованного запроса.
