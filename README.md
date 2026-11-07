# ElXray

[![Тесты ядра](https://github.com/ElXnet/ElXray/actions/workflows/subscription-policy.yml/badge.svg?branch=main)](https://github.com/ElXnet/ElXray/actions/workflows/subscription-policy.yml)
[![Go vet](https://github.com/ElXnet/ElXray/actions/workflows/elx-go-vet.yml/badge.svg?branch=main)](https://github.com/ElXnet/ElXray/actions/workflows/elx-go-vet.yml)
[![MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)

**ElXray** — форк [XTLS/Xray-core](https://github.com/XTLS/Xray-core) для VPN-платформы **ElX (ElectriumX)**. Поверх стандартного ядра Xray добавлены **исполняемые ограничения подписок**, безопасные runtime-изменения скорости и криптографические подтверждения, необходимые для согласования нескольких VPN-нод через [ElX Control](https://github.com/ElXnet/ElX-control).

> **Статус:** ключевые расширения реализованы и покрыты локальными сетевыми, конкурентными и интеграционными тестами. Это не подтверждает стабильность всех протоколов, транспортов, физических устройств и сетей в реальной эксплуатации.

## Что добавлено поверх Xray-core

### 1. Лимиты подписки во время работы

- Общая квота на **несколько серверных пользователей/e-mail** одной подписки внутри **одного процесса ElXray**.
- **Независимые** направления upload и download, общий token bucket для параллельных потоков; множественные TCP-соединения и IP не создают дополнительный бюджет.
- Обновление обеих скоростей и `disabled` во время работы, с атомарной проверкой ревизии и защитой от устаревших команд и их повторной доставки.
- Запрет немаппированных пользователей при `policy.requireSubscription=true`; запрет `0` в runtime-обновлениях скорости (случайный unlimited не допускается).
- Защита от обхода квоты через пути raw socket splice, включая Vision, с сохранением корректной работы статистики.

**Важно:** лимит внутри ElXray — **локальный для ноды**. Межнодовой общий бюджет назначает Control; ElXray не синхронизирует произвольные ноды напрямую. Скорости конфигурации задаются в **байтах в секунду (B/s)**: например, 100 Мбит/с = `12 500 000` B/s **в каждом** направлении.

### 2. Подписанные политики, подтверждения и закрытие сессий

- Краткосрочные **подписанные Control leases** с проверкой срока, закреплённой идентичности ядра и разрешённой полосы. При обязательном режиме истёкшее разрешение блокирует дальнейший доступ.
- Проверка поколения сессии, запрет новых VLESS-потоков и закрытие установленных соединений (включая idle) через управляемый **deny/drain**. Освобождать занятый слот Control может только по подходящему подписанному доказательству от актуального ядра.
- **Signed rate barrier** подтверждает снижение полосы до того, как Control передаст освобождённый бюджет другой ноде; при положительной сниженной скорости действующие VPN-соединения сохраняются.
- **Ed25519 evidence** от ядра: подписанные показания накопительного трафика, насыщения лимитера по направлениям и фактически принятого подписанного lease, привязанные к nonce, ноде и экземпляру ядра.
- Защита от старых policy revisions, повторов и несовпадающих идентификаторов. При ошибке применения уже действующая корректная политика сохраняется.

### 3. Исправления качества и проверок

- Устранена гонка обновления TLS-сертификатов во время handshake.
- Добавлены интеграционные матрицы VLESS/TCP, Vision с TLS/REALITY, UDP, XUDP и mux, а также тесты снижения скорости без переподключения.
- Настроены самостоятельные CI-проверки форка, проверка необходимых geodata и синхронизация upstream через контролируемые PR; последние [PR #16](https://github.com/ElXnet/ElXray/pull/16) и [#17](https://github.com/ElXnet/ElXray/pull/17) укрепили полный прогон, обновили зависимости и добавили полный `go vet`.
- Изменения [PR #14](https://github.com/ElXnet/ElXray/pull/14) были перенесены в **#16**: отдельный #14 закрыт **без merge** и не должен фигурировать как отдельно слитый PR.

## В составе ElX

```text
ElX-ui  ── локальный защищённый API ──► ElX Control
                                             │
                                         mTLS-агент
                                             │
                                   локальный API ElXray
                                             │
                               VLESS / REALITY / Xray data plane
```

ElXray **не хранит** тарифы, платежи и учётные записи ЛК, не определяет физическое устройство по HWID/IP и не публикует межнодовой административный API. Постоянное состояние прав, журнал и глобальные лимиты относятся к [ElX-control](https://github.com/ElXnet/ElX-control); администрирование и интерфейс пользователя — к [ElX-ui](https://github.com/ElXnet/ElX-ui).

## Сборка

Потребуется Go согласно [go.mod](go.mod) (сейчас заявлена ветка 1.27).

```bash
go build -o elxray ./main
./elxray version
./elxray run -config config.json
```

В Windows:

```powershell
go build -o elxray.exe ./main
.\elxray.exe version
```

Для совместимости с исходным кодом и protobuf сохранены `module github.com/xtls/xray-core` и исходные пространства имён; **название собранного продукта — ElXray**. Не следует считать официальный бинарник Xray-core взаимозаменяемым с ElXray при включённых политиках ElX.

## Минимальный пример политики

В существующей серверной конфигурации (это **фрагмент**, не самостоятельный конфиг) можно задать:

```json
{
  "policy": {
    "requireSubscription": true,
    "subscriptions": {
      "account-123": {
        "emails": ["account-123@example"],
        "uplinkBps": 12500000,
        "downlinkBps": 12500000,
        "revision": 1,
        "disabled": false
      }
    }
  }
}
```

Пример задаёт **100 Мбит/с upload и 100 Мбит/с download** на одну ноду. `0` в стартовой конфигурации может означать unlimited, однако runtime RPC не разрешает ставить `0`; Control должен назначать положительные согласованные гранты. Защищённый локальный API может использовать `127.0.0.1:10085` или Unix-сокет; публиковать его в LAN/Интернет нельзя.

При обновлении скорость меняется у существующих потоков; **runtime-политика хранится в памяти**, поэтому внешний supervisor должен сохранять согласованную ревизию и восстанавливать её после запуска. Подробные правила, допустимые ошибки и способы обновления — в [контракте API](docs/electrium/RUNTIME_API.md).

## Документация

| Раздел | Где читать |
| --- | --- |
| Правила лимитов, направления, bursts и ограничения | [SUBSCRIPTION_RATE_LIMIT](docs/electrium/SUBSCRIPTION_RATE_LIMIT.md) |
| Конфигурация, локальный gRPC/CLI API, ревизии | [RUNTIME_API](docs/electrium/RUNTIME_API.md) |
| Подписанные подтверждения фактически принятого lease | [SIGNED_LEASE_ACCEPTANCE](docs/electrium/SIGNED_LEASE_ACCEPTANCE.md) |
| Подписанное давление лимитера | [LIMITER_PRESSURE](docs/electrium/LIMITER_PRESSURE.md) · [SIGNED_PRESSURE_EVIDENCE](docs/electrium/SIGNED_PRESSURE_EVIDENCE.md) |
| Безопасное обновление из upstream | [UPSTREAM_SYNC](docs/electrium/UPSTREAM_SYNC.md) |
| Сценарии локального стенда, SOCKS/TUN, сетевые тесты | [Тестовый стенд](testing/subscriptionrate/README.md) |
| Полная межрепозиторная приёмка | [ElX Control: техническая приёмка](https://github.com/ElXnet/ElX-control/blob/main/docs/elx/technical-acceptance-2026-11-07.ru.md) |

Точные поля protobuf и методы внутреннего API вынесены в `docs/electrium/`, а не дублируются в главном README.

## Тестирование

```bash
go test -race ./common/subscriptionrate ./app/dispatcher ./app/policy ./app/policy/command ./common/buf ./proxy ./testing/subscriptionrate -count=1 -timeout 120s
go test -race ./infra/conf -run '^TestSubscription' -count=1 -timeout 90s
go test ./...
go vet ./...
python3 -m unittest discover -s testing/subscriptionrate -p 'test_*.py' -v
```

Для полного `go test ./...` необходимы `resources/geoip.dat` и `resources/geosite.dat`, а некоторые тесты upstream обращаются к Интернету. Часть тестов с `-race` требует установленного C toolchain. Соответствующие CI настраивают и проверяют зависимости отдельно.

Комплексное тестирование **Control ↔ две локальные ElXray-ноды ↔ ElX-ui** запускается из [ElX-control](https://github.com/ElXnet/ElX-control). Оно охватывает подписи, конкурирующие сессии, сетевые разделения, FUP и перераспределение скорости, но **не подменяет испытания на реальных устройствах и удалённых VPS**.

## Ограничения

- Физическое количество устройств не следует определять по числу соединений, IP или HWID; копирование стандартного ключа остаётся отдельным продуктовым риском.
- Token bucket допускает ограниченный burst и не гарантирует ни равные доли между устройствами, ни математически точное packet-level ограничение на сетевой карте.
- Подписанное принятие lease — не то же, что новый handshake или физический идентификатор устройства; подписанный quiet barrier не подтверждает опустошение всех буферов ОС.
- Не все транспорты и комбинации Xray испытаны; отсутствие связи с Control безопасно только при **правильно включённом обязательном режиме leases**.
- WebRTC-транспорт и гарантированный обход сетевых ограничений **не заявлены как готовые функции**.

## Происхождение и лицензия

ElXray — независимый форк [XTLS/Xray-core](https://github.com/XTLS/Xray-core). Исходные уведомления об авторстве сохраняются; дополнительные возможности ElX не являются официальными функциями upstream. Лицензия — [MPL-2.0](LICENSE).
