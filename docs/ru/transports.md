# Транспорты прокси

HTTPS и SSH остаются базовыми транспортами. HTTP/3 и SOCKS5 включаются отдельно
на каждом HTTPS-хосте и используют существующий GOST и пользователей `users.https`.
По умолчанию оба выключены.

```yaml
hosts:
  proxy_example:
    # address и admin как у обычного прокси
    services:
      https:
        endpoint: proxy.example.com
        certificate: domain
        acme_email: admin@example.com
        http3: true
        masque_profiles: false
        socks5:
          enabled: false
          port: 1080
          udp_port_min: 40000
          udp_port_max: 40100
```

## HTTP/3 и MASQUE

`http3: true` добавляет GOST MASQUE с listener `http3`, TLS 1.3 и HTTP Datagrams.
Это отдельный UDP-listener, обычный HTTPS/TCP продолжает работать. На прямом
маршруте UDP использует тот же номер порта, что HTTPS, обычно 443. Firewall открывает
нужный UDP-порт. Контейнеру добавляется только capability `NET_BIND_SERVICE`,
необходимая для привязки низких портов.

API подписок и MegaProxy JSON выставляют `proxy.preferHttp3: true` только когда
HTTPS и MASQUE доступны на одном hostname и номере порта. Android пробует QUIC,
а при поддерживаемых контрактом ошибках возвращается к HTTPS/TCP. Ошибки проверки
сертификата и аутентификации остаются отказами.

`masque_profiles: true` дополнительно публикует отдельные профили `type: MASQUE`.
Этот параметр требует `http3: true`; он не нужен для HTTPS с `preferHttp3`.
Отдельный MASQUE-профиль требует HTTP/3 и не переключается на HTTPS.
Профили получают логин и пароль текущего авторизованного пользователя.

HTTP/3 включается только на прямых маршрутах. Серверные SNI-цепочки остаются HTTPS/TCP
и не получают MASQUE или `preferHttp3`: GOST 3.3.0 передаёт некорректный Extended CONNECT
при собственном исходящем CONNECT-UDP. Это ограничение не разрешает превращать
цепочку в прямой маршрут. В нашем inventory HTTP/3 на хостах `cpx-*` выключен.
Клиентские HTTPS_JUMP-профили могут описывать два прямых HTTPS/MASQUE endpoint;
их поддержку и fallback реализует клиент согласно контракту MegaProxyConfig.

Маскировка GOST (`probe_resistance`) относится к HTTPS/TCP. Она сохраняет сайт-приманку,
robots.txt и настроенные knock-хосты. На UDP/MASQUE knock и сайт-приманка не применяются.
HTTP/3/MASQUE в GOST и клиентах остаются экспериментальными. Browser-проекции API
сохраняют совместимые HTTPS/SOCKS5; MASQUE доступен в полном и Android-ответе.

## SOCKS5 — не рекомендуется

**SOCKS5 не рекомендуется из-за проблем с безопасностью:** протокол не шифрует
транспорт. RFC 1929 передаёт логин и пароль без шифрования, а незашифрованный трафик
приложений также доступен наблюдателю. HTTPS приложения защищает содержимое своего
соединения, но не защищает SOCKS5-аутентификацию. Используйте HTTPS/MASQUE или SSH.

Для явного включения задайте `services.https.socks5.enabled: true`. Сервер требует
логин и пароль из `users.https`, не разрешает анонимный доступ и поддерживает TCP
CONNECT и UDP ASSOCIATE. Реквизиты ограничены 255 UTF-8 байт каждый.
SOCKS5 публикуется на прямом endpoint хоста; серверные HTTPS-цепочки к нему не применяются.

Firewall открывает TCP `port` и заданный диапазон UDP-relay. Число одновременно
выделенных relay-портов ограничено размером диапазона; измените диапазон, если его
недостаточно. На отключённом SOCKS5 listener и эти правила не создаются.

API автоматически выдаёт SOCKS5-профили только для включённых хостов. Firefox и
Android получают профили с реквизитами; Chromium их пропускает, поскольку не
поддерживает SOCKS5-аутентификацию. ProxyList/SuperProxy/FoxyProxy остаются HTTPS-экспортами;
новые транспорты включаются в MegaProxy JSON v8. Без них прежний JSON остаётся v7.

## Проверка

```sh
./mega-proxy validate
./mega-proxy plan --limit proxy_example
./mega-proxy apply --limit proxy_example
./mega-proxy verify --limit proxy_example
```

Изменения флагов нужно применить и на прокси, и на серверах конфигов. `--limit`
обновляет только выбранные машины. Отключение listener прекращает доступ; роль
firewall добавляет необходимые правила, но не удаляет ранее созданные правила.

Тесты генерации и совместимости входят в `./mega-proxy check`. Проверка реального
GOST 3.3.0 локально и в CI:

```sh
uv run python tests/integration/transports.py --gost /path/to/gost
```

Она проверяет SOCKS5 TCP/UDP, обязательную аутентификацию, диапазон relay-портов,
MASQUE TCP/UDP, доверенный TLS и отказ при неверных реквизитах.
В тестах используются временные ключи и реквизиты; публичные серверы не требуются.

Исходные настройки: [MASQUE GOST](https://gost.run/reference/handlers/masque/),
[HTTP/3 listener](https://gost.run/en/reference/listeners/http3/),
[контракт MegaProxyConfig](https://github.com/andre487/MegaProxyConfig/blob/5c0758c/docs/configuration.md).
