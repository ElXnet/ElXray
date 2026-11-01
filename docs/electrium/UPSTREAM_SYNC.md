# Обновление ElXray из релизов Xray-core

Workflow `.github/workflows/upstream-sync.yml` проверяет последний стабильный релиз XTLS/Xray-core раз в шесть часов (UTC) и по кнопке Run workflow. Он начинает работу только после попадания файла в main. Релизы pre-release не применяются.

## Однократная настройка

1. Слейте PR с этим workflow в main после успешных проверок.
2. В профиле GitHub: Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token.
3. Resource owner — владелец ElXray. Repository access → Only select repositories → ElXray. Задайте срок действия токена, например 90 дней.
4. Repository permissions: Contents → Read and write; Pull requests → Read and write; Workflows → Read and write. Metadata → Read-only добавляется автоматически. Остальные права не нужны. Workflows требуется, потому что upstream-релиз может менять файлы .github/workflows.
5. Нажмите Generate token и скопируйте токен. Не публикуйте его в чате, файлах или коммитах.
6. В репозитории ElXray: Settings → Secrets and variables → Actions → New repository secret. Name: `UPSTREAM_SYNC_TOKEN`. Secret: созданный токен. Нажмите Add secret.
7. Settings → General → Pull Requests → Allow auto-merge должно быть включено.
8. Активный Ruleset на `main` должен требовать PR, актуальную базовую ветку (strict checks) и все восемь проверок: `check-assets`, `check-format-and-proto`, `test (ubuntu-latest)`, `test (windows-latest)`, `test (macos-latest)`, `local-regression (ubuntu-latest)`, `local-regression (windows-latest)`, `local-regression (macos-latest)`. У токена не должно быть bypass этих требований. Не путайте имя workflow с именем status check: используются имена jobs из GitHub Actions. `check-assets` — проверка из `.github/workflows/test.yml`; в release-workflows подготовка ресурсов имеет отдельные имена `prepare-release-assets` и `prepare-win7-assets`, поэтому их результаты не конфликтуют с обязательной проверкой.
9. Actions → Sync Xray upstream release → Run workflow → main → Run workflow.

Без секрета ручной/плановый запуск завершится понятной ошибкой. При истечении токена создайте новый с теми же правами и обновите значение секрета.

## Поведение

- Если релиз уже присутствует в истории main, изменений нет.
- При наличии открытого PR `updates/xray-*` новые обновления ждут завершения этого PR. Существующие ветки не перезаписываются и force push не используется.
- При чистом merge обновляется сгенерированный Protobuf-код (`*.pb.go`) для версии инструментов нового релиза, затем создаётся обычный PR с объединённой историей: наши коммиты сохраняются. Если генерация не удалась, задача завершается ошибкой до создания PR, а `main` остаётся неизменным. Проверка `check-format-and-proto` остаётся обязательной.
- Auto-merge запрашивается только при обнаружении активных правил с PR, полным набором из восьми обязательных проверок и требованием актуальной базы. Если правил/прав недостаточно, PR остаётся для ручного слияния. GitHub, а не скрипт, проверяет выполнение требований.
- При конфликте merge отменяется и создаётся Draft PR. Он содержит только `.github/upstream-conflict.json` с версией, SHA и перечнем конфликтов — само обновление в него ещё НЕ включено. Auto-merge для него не включается.
- Для конфликтного PR нужно локально объединить записанный upstream commit с его веткой, разрешить конфликты, удалить JSON-маркер, отправить результат, пройти CI и только затем отметить PR готовым.
- Если PR закрыт без слияния, его сохранённая ветка препятствует автоматическому повторному созданию того же обновления. Для повторной попытки откройте прежний PR либо вручную удалите его ветку после проверки.

Токен используется вместо GITHUB_TOKEN, чтобы push и PR запускали CI без отдельного подтверждения workflows. Сам workflow обновления не запускается на pull_request с секретом: на PR выполняются только тесты скрипта.

Проверки форматирования, Protobuf и полные Go-тесты должны выполняться на PR **до** слияния, а не только на push после него. Из-за пропуска jobs на внутренних PR обновление v26.10.29 прошло в `main` до обнаружения двух ошибок; это условие удалено в исправляющей ветке.

После слияния штатный push запускает существующие сборки ElXray. Этот механизм не развёртывает бинарники на серверах и не создаёт опубликованный GitHub Release автоматически.

Тесты логики обновления без GitHub и токенов:

```sh
python3 -m unittest discover -s .github/scripts -p test_sync_upstream.py -v
```
