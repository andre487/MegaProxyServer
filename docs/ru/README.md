# Руководство MegaProxyServer

[English version](../en/README.md) · [Обзор проекта](../../README.md)

## Назначение

MegaProxyServer разворачивает HTTPS- и SSH-прокси на нескольких серверах Debian/Ubuntu. Python CLI
проверяет единый inventory и создаёт переменные Ansible, клиентские конфигурации и компактный summary
реквизитов. Ansible устанавливает и поддерживает серверные компоненты.

HTTPS обслуживает GOST в контейнере закреплённой версии. HAProxy маршрутизирует TLS по SNI, когда
один входной сервер публикует несколько chain-доменов. Системные пользователи SSH-прокси ограничены
локальным TCP forwarding: им недоступны shell, TTY, subsystem, remote forwarding и tunnel device.

## Требования

Управляющей машине нужны macOS или Linux, `uv`, OpenSSH и Python 3.12+. Управляемым машинам —
актуальный Debian или Ubuntu и SSH-пользователь с `sudo`. Откройте TCP 443 для HTTPS и TCP 80 на
время standalone-проверки ACME как в firewall провайдера, так и на самом сервере.

ACME-сертификаты на публичный IP требуют Certbot 5.4+ и short-lived profile Let's Encrypt.

## Первое развёртывание

```shell
./mega-proxy inventory
./mega-proxy plan
./mega-proxy apply
./mega-proxy verify
```

Мастер создаёт административные ключи, реквизиты прокси и зашифрованный inventory. Путь к inventory
вне репозитория сохраняется в игнорируемом `inventory-path`. Параметр `--inventory PATH` всегда имеет
приоритет.

Для первого подключения используется `admin.bootstrap_user`. После успешного полного apply CLI
создаёт постоянного администратора, устанавливает его ключ и удаляет `bootstrap_user` из inventory.
Не закрывайте исходную SSH-сессию, пока не проверите постоянный логин.

## Команды

| Команда | Назначение |
| --- | --- |
| `inventory` | Интерактивно создать inventory |
| `validate` | Проверить модель данных и синтаксис Ansible |
| `plan` | Запустить provisioning в режиме check/diff |
| `apply` | Развернуть или обновить серверы |
| `verify` | Проверить готовое развёртывание |
| `summary [LOGIN]` | Вывести endpoint-ы и глобальные реквизиты |
| `configs` | Создать все клиентские форматы |
| `export [--all-jumps]` | Экспортировать JSON для MegaProxy |
| `jumps` | Показать направленные комбинации SSH jump |
| `remove-users` | Отметить глобальных пользователей для удаления |
| `vault-secrets` | Зашифровать секретные поля inventory |
| `check` | Запустить локальные и CI-проверки |

Для `plan`, `apply` и `verify` доступны `--limit HOST` и `--tags`. Теги provisioning: `common`,
`admin`, `firewall`, `ssh`, `https`.

```shell
./mega-proxy apply --limit proxy_eu --tags https
```

Параметр `--no-hooks` до или после команды отключает локальные post-change интеграции.

## Inventory

Начните с [`inventory.example.yml`](../../inventory.example.yml). Пользователи прокси глобальны и
устанавливаются на каждый хост с включённым соответствующим сервисом. Поэтому реквизиты одного
логина не могут незаметно различаться между серверами.

```yaml
version: 1
settings:
  manage_firewall: true
  unattended_upgrades: true
  https_chains_enabled: true
  https_chain_domain: chains.example.com
  https_chain_backend_port: 10443
  https_chain_pairs:
    - entry: entry_eu
      exit: exit_us
      country_code: US
      hostname: eu-via-us.example.com
      title: EU -> US

users:
  https:
    - name: alice
      password: REPLACE_WITH_AT_LEAST_16_CHARACTERS
  ssh:
    - name: tun-alice
      authentication:
        type: key
        public_key: ssh-ed25519 REPLACE_WITH_PUBLIC_KEY
        generated_private_key: ~/.ssh/megaproxy_alice
  removed_ssh: []

hosts:
  entry_eu:
    address: 203.0.113.10
    admin:
      user: deploy
      bootstrap_user: root
      port: 22
      private_key_file: ~/.ssh/id_ed25519
      public_key: ssh-ed25519 REPLACE_WITH_ADMIN_PUBLIC_KEY
    services:
      https:
        endpoint: proxy-eu.example.com
        title: EU
        certificate: domain
        acme_email: admin@example.com
        chain_entry: true
        chain_exit: false
        direct: true
      ssh:
        port: 22
```

### Глобальные настройки

- `manage_firewall`: управлять правилами UFW.
- `unattended_upgrades`: включить автоматические security updates.
- `https_chains_enabled`: включить HTTPS-маршруты entry/exit.
- `https_chain_domain`: базовый домен автоматически создаваемых chain-имён.
- `https_chain_backend_port`: первый loopback-порт chain backend-ов.
- `https_chain_pairs`: необязательный allow-list маршрутов; для каждой объявленной пары обязателен
  двухбуквенный `country_code` выходного прокси, также пара может переопределить `hostname` и `title`.

При пустом `https_chain_pairs` создаются все совместимые комбинации entry→exit. Непустой список
ограничивает генерацию явно объявленными парами.

### HTTPS-сервис

- `endpoint`: публичное DNS-имя или IP-адрес.
- `title`: отображаемое имя для px-manager, summary и клиентских экспортов.
- `port`: публичный порт, по умолчанию `443`.
- `certificate`: `domain`, `ip-acme` или `self-signed`.
- `acme_email`: обязателен для `domain` и `ip-acme`.
- `gost_version` и `certbot_version`: закреплённые версии контейнеров.
- `chain_entry` и `chain_exit`: разрешить участие в HTTPS chains.
- `direct`: публиковать собственный прямой HTTPS-маршрут.
- `chain_username` и `chain_password`: машинные реквизиты между chain-узлами. Каждому exit нужен
  пароль; в пользовательские экспорты он не попадает.
- `probe_resistance`: необязательный ложный ответ для неаутентифицированных запросов. По умолчанию
  выключен, потому что браузеры получают сохранённые proxy-реквизиты только после ответа `407`, а
  decoy его подавляет. Явное включение может нарушить аутентификацию браузерных proxy-клиентов.
  Необязательный список `knock` задаёт hostname-ы, для которых GOST возвращает обычный `407`.

Приоритет title цепочки: `title` пары, `title` HTTPS-сервиса входного узла, затем title, полученный из
имени хоста в inventory.

### SSH-сервис

Поддерживаются `port`, `max_startups`, `per_source_max_startups` и `fail2ban`. Пользователи могут
использовать `key` или `password`. Для пароля хранятся открытое значение для клиентского экспорта и
серверный хеш. Для ключа — публичный ключ и локальный путь к приватному ключу для экспорта MegaProxy.

## HTTPS-сертификаты и chains

Доменные сертификаты выпускаются Certbot в standalone-режиме. Сертификат entry-сервера содержит его
direct endpoint, если он включён, и все chain-домены. После добавления пары роль находит отсутствующий
SAN, расширяет сертификат и перезапускает GOST, чтобы сертификат загрузился сразу.

До `apply` каждое chain-имя должно резолвиться в entry-сервер. HAProxy читает SNI без терминации TLS
и передаёт соединение отдельному GOST HTTP/2 listener на loopback. Затем entry подключается к
выбранному exit по машинным реквизитам. Отдельная пара в `https_chain_pairs` может переопределить
`probe_resistance` только для своего chain-маршрута.

Обновление сертификатов запускается systemd timer. Self-signed — явный запасной режим, в котором
клиент должен разрешить недоверенный сертификат прокси.

## Клиентские конфигурации

```shell
./mega-proxy configs
./mega-proxy configs --output-dir /secure/path
```

По умолчанию `.generated/configs` содержит:

- `MegaProxy.json`: HTTPS, прямые SSH и все динамические SSH jump-профили;
- `FoxyProxy.json`: HTTPS-профили;
- `SuperProxy.txt`: HTTPS URL с заголовком Super Proxy v1;
- `ProxyList.txt`: URL-кодированные HTTPS-прокси.

Каталог получает права `0700`, файлы — `0600`. Генерация идемпотентна и не подключается к серверам.
Экспорты содержат открытые пароли и приватные ключи — обращайтесь с ними как с секретами.

## Summary

`./mega-proxy summary` один раз выводит endpoint-ы, затем по одному разу глобальные реквизиты:

```text
Hosts:
proxy-eu.example.com (EU, HTTPS, SSH)
eu-via-us.example.com (EU -> US, HTTPS)

HTTPS:
alice
PASSWORD

SSH:
tun-alice
/path/to/private/key
```

`summary alice` выбирает точное совпадение proxy-login. Административные пользователи не выводятся.
Не сохраняйте результат в незащищённый файл или CI-лог.

## Пользователи, Vault и hooks

`remove-users` удаляет HTTPS-пользователей из всех конфигураций GOST. Удаляемые SSH-пользователи
также попадают в глобальный tombstone-список `removed_ssh`; следующий apply удаляет их системные
аккаунты и root-owned authorized-key файлы на всех SSH-хостах. Последнего пользователя включённого
сервиса удалить нельзя.

`vault-secrets` шифрует отдельные секреты как tagged-значения Ansible Vault, оставляя хосты, порты и
флаги читаемыми. Шифрование сохраняется при дальнейших изменениях. Для unattended-запуска задайте
`ANSIBLE_VAULT_PASSWORD_FILE`, иначе CLI запросит пароль.

После успешного apply запускаются исполняемый `.hooks/post-config-change` и файлы из
`.hooks/post-config-change.d/` в порядке имён. Они получают `MEGAPROXY_INVENTORY`,
`MEGAPROXY_ANSIBLE_INVENTORY`, `MEGAPROXY_ROOT`, `MEGAPROXY_EVENT`. Игнорируемый каталог `.hooks`
подходит для локальных интеграций, например px-manager.

## Безопасность и эксплуатация

- Считайте inventory, `.secrets`, `.generated`, summary и экспорты секретными.
- Создавайте отдельный аккаунт или ключ для каждого человека или устройства.
- Проверяйте SSH fingerprint по доверенному каналу.
- Root SSH login отключается; постоянный администратор использует ключ и имеет sudo.
- Правила firewall облачного провайдера остаются ответственностью оператора.
- Опциональный Probe Resistance скрывает протокол от неаутентифицированных HTTP-проб, но не IP
  сервера или SNI; включайте его только после проверки нужных клиентов.

## Разработка и диагностика

`./mega-proxy check` запускает Ruff, pytest, byte-compilation и проверку синтаксиса Ansible. CI
выполняет тот же набор; интеграционные jobs разворачивают изолированные Ubuntu/Debian LXD-системы.

- **Ошибка ACME:** проверьте DNS, TCP 80 и firewall провайдера.
- **Chain-домен отдаёт старый сертификат:** выполните `apply --limit ENTRY --tags https`, затем
  проверьте SAN сертификата и статус `megaproxy-gost`.
- **Выбран не тот inventory:** передайте `--inventory PATH` или проверьте `inventory-path`.
- **Не обновился px-manager:** проверьте executable bit hook-а и отсутствие `--no-hooks`.
