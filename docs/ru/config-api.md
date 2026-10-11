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

## Явные jump-пары

Прямые SSH-профили генерируются только для отмеченных хостов:

```yaml
hosts:
  de_proxy:
    services:
      ssh:
        title: DE
        enabled: true
        generate_profile: true
```

`generate_profile` по умолчанию false; флаг действует на API, `export` и `configs`.
Он управляет только прямым клиентским профилем. Явные SSH jump-пары могут использовать
хост без этого флага, если SSH-сервис включён.

`enabled` по умолчанию true и управляет настройкой и проверкой SSH-прокси на сервере.
При false SSH-профили для хоста не генерируются, ссылки на него в jump-парах отклоняются.
Этот флаг не отключает административный SSH и не удаляет ранее созданные аккаунты:
роль SSH-прокси просто пропускается. Для отзыва аккаунта используйте `remove-users` и `apply`.

Названия прямых SSH-профилей берутся из обязательного `services.ssh.title`.
API выдаёт title без логина; общий экспорт добавляет ` / логин`, как для HTTPS.
Название SSH jump-пары берётся из её обязательного `title`.
Изменение title сохраняет ID прямого SSH-профиля в API и файловом экспорте.

```yaml
settings:
  ssh_jump_pairs:
    - entry: de_proxy
      exit: us_proxy
      title: SSH DE -> US
      country_code: US
  https_jump_pairs:
    - entry: de_proxy
      exit: us_proxy
      title: DE -> US
      country_code: US
```

`entry` — входной jump-хост, `exit` — конечный прокси. SSH-пара использует один и тот же аккаунт из
`users.ssh` на обоих узлах. Экспорт создаёт профиль для каждого SSH-аккаунта,
API — только для аккаунтов из `ssh_users` пользователя. HTTPS-пара использует
его HTTPS-реквизиты на обоих узлах; `title` обязателен, `country_code` необязателен,
страна берётся у выхода. Для HTTPS Jump оба
хоста должны иметь включённый прямой HTTPS endpoint; настройки серверных цепочек не нужны.

Для SSH-пар `title` также обязателен, `country_code` необязателен:
страна берётся из имени выходного хоста.

Пустые `ssh_jump_pairs` и `https_jump_pairs` не создают jump-профилей. Прямые профили
остаются. `export` и `configs` также используют только заданные пары; `--all-jumps`
сохранён для совместимости и не включает перебор комбинаций. Неизвестные хосты и
выключенные сервисы, совпадение entry/exit и повторные пары отклоняются.

`https_chain_pairs` — отдельная настройка серверных SNI-цепочек: она создаёт обычные
HTTPS-профили с отдельными hostname. Пустой список больше не включает все комбинации.

Полные примеры: [клиентские jump-пары](../../inventory.jumps.example.yml)
и [серверные цепочки](../../inventory.chains.example.yml).

## Порядок профилей

API и MegaProxy JSON формируют группы в следующем порядке: прямые HTTPS, прямые SSH,
`https_chain_pairs`, `https_jump_pairs`, `ssh_jump_pairs`. Прямые профили следуют порядку
хостов в inventory; цепочки и jump-пары — порядку соответствующих списков, без сортировки
по имени выходного хоста. При нескольких аккаунтах они следуют порядку списка пользователей.
MASQUE и SOCKS5 входят в группу прямых HTTPS-транспортов. Дополнительные
`client_config.profiles` добавляются в конце в заданном порядке. ID от перестановки не меняются.
FoxyProxy, SuperProxy и ProxyList содержат сначала прямые HTTPS, затем серверные цепочки.

## Запросы и доступ

`GET /api/config` принимает Basic Auth с UTF-8 логином и паролем из `users.https`.
Сервис проверяет пару через scrypt с индивидуальной случайной солью, после чего создаёт
MegaProxy JSON v8 непосредственно для запроса. Логин и пароль HTTPS-профилей берутся
из запроса, а не из сохранённого открытого конфига. Каждый пользователь получает свои
HTTPS-профили всех маршрутов inventory.

Названия HTTPS-профилей берутся из обязательного `services.https.title`,
а серверных цепочек — из `title` пары, без добавления логина.
Отсутствующий или пустой `title` отклоняется при проверке inventory. Код страны прямого маршрута
берётся из первого сегмента имени без `proxy_`; для цепочки — из `country_code`
пары или имени выходного хоста. В конфиг попадают только двухбуквенные коды.

SSH-профили доступны только через явные привязки:

```yaml
users:
  https:
    - name: alice
      password: REPLACE_WITH_AT_LEAST_16_CHARACTERS
      ssh_users: [tun-alice]
```

Для этих аккаунтов выдаются прямые SSH-профили хостов с `generate_profile: true`
и только явно заданные `ssh_jump_pairs`.
Аккаунт jump-профиля должен входить в привязки пользователя. SSH-пароли и приватные
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

Настройка генерации новых транспортов описана в [Транспортах прокси](transports.md).
`services.https.http3` включает поддержку и флаг предпочтения HTTP/3 на совместимых
HTTPS-маршрутах; отдельные MASQUE-профили требуют `masque_profiles: true`.
SOCKS5-профили генерируются только при `socks5.enabled: true`; SOCKS5 не рекомендуется
из-за отсутствия шифрования транспорта и реквизитов аутентификации.

Используются [формат v8](https://github.com/andre487/MegaProxyConfig/blob/5c0758c855712415bf2f1dfd6f9a97fd92d5dfee/docs/configuration.md)
и [протокол доставки](https://github.com/andre487/MegaProxyConfig/blob/5c0758c855712415bf2f1dfd6f9a97fd92d5dfee/docs/subscription-protocol.md).
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
стабильными ID. Это позволяет описать дополнительные HTTPS_JUMP, SOCKS5 и MASQUE endpoints,
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

Для запроса с реквизитами из файла:

```text
machine configs.example.com
login alice
password REPLACE_WITH_HTTPS_PASSWORD
```

```sh
chmod 600 credentials.netrc
curl --fail --silent --show-error --basic --netrc-file ./credentials.netrc \
  https://configs.example.com/api/config | jq '.profiles | length'
```

Проверить состав профилей без вывода реквизитов можно через
`jq '.profiles | group_by(.proxy.type) | map({type: .[0].proxy.type, count: length})'`.

В варианте `--user alice` curl запросит пароль, не помещая его в историю команды.
В варианте `--netrc-file` реквизиты читаются из файла. `apply` самостоятельно собирает
пакет и доставляет его только API-хостам. Неизменившиеся данные сохраняют шифротекст и
права файлов; обновления записываются атомарно. Удаление аккаунта удаляет его запись доступа.

После изменения `generate_profile`, jump-пар, title или страны повторите `configs` для
файлового экспорта и `apply --limit ИМЯ_API_ХОСТА` для каждого API-хоста подписки.
Эти параметры управляют генерацией конфигов. Изменения серверных сервисов, пользователей
или `https_chain_pairs` нужно также применить на затронутых прокси.

Локальный тест с настоящим nginx и временным доверенным тестовым сертификатом:

```sh
uv run python tests/integration/config_api.py --nginx /path/to/nginx
```

Он проверяет HTTPS, canonical v8, ETag после аутентификации, robots.txt, буквальное сравнение
путей и ответы 403/noindex. В рабочие API-пакеты не входят полный inventory, административные
ключи, исходные пути SSH-ключей или машинные пароли HTTPS-цепочек. Работающий API получает
пароль и расшифрованные SSH-секреты в памяти во время авторизованного запроса.


Knock host для замаскированного HTTPS-прокси задаётся в inventory:
`services.https.probe_resistance.knock: [px-knock.jethelix.ru]`.
Первый хост списка становится `browser.knockHost` в API и файловом экспорте MegaProxy;
для MASQUE он не применяется. Мастер настройки запрашивает его при включении маскирования.
Серверные цепочки наследуют настройку entry, если у пары нет своего `probe_resistance`.
После изменения примените HTTPS-настройки на прокси и обновите bundle API.
