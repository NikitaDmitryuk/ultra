# Установка и эксплуатационная автоматизация

## Полная замена production

`make deploy` — единственный штатный production deployment entrypoint. Он
разворачивает committed candidate как полную destructive replacement non-DB
окружения: старые bridge/exit runtime, deployment journals, admission markers,
worker jobs, receipts и другая deployment metadata отбрасываются. Старая
операция не возобновляется, не откатывается и не reconcile-ится. Допустим полный
простой VPN.

Обычный deploy не требует operator-supplied database backup, digest, restore
receipt или дополнительного ACK. PostgreSQL primary остаётся на месте. До и
после замены проверяются identity primary и её schema; DB host не входит в набор
заменяемых серверов. Рутинная замена не делает dump, restore или import и не
запускает migrations и не меняет прикладные таблицы, данные или версию миграций.
Для статуса реплики bootstrap может заново создать только служебные объекты
`ultra_monitor` и их grants в каталоге PostgreSQL.

Recovery preparation, backup readiness и automation recovery — вспомогательный
контур и не входят в readiness VPN. При этом bootstrap устанавливает controller,
fleet identity и Vultr provider integration для пользовательских cloud lifecycle
операций. Core service readiness проверяет VPN relay, ingress и настроенный бот;
замена сохраняет Telegram bot, Mini App и создание, проверку, замену и удаление
cloud nodes.

## Канонические входы и запуск

`install.config` содержит несекретную топологию и параметры установки. Секреты
остаются в `.env` и отдельных приватных ключах. Для запуска из чистого tracked
дерева и committed `HEAD`:

```sh
ULTRA_OPERATOR_IDENTITY=/secure/operator/ssh-key \
ULTRA_OPERATOR_KNOWN_HOSTS=/secure/operator/known_hosts make deploy
```

Операторский SSH identity должен быть выделенным локальным ключом с правами 0600,
а `known_hosts` — содержать ключи целевых серверов, проверенные через доверенный
источник провайдера. `ssh-keyscan` сам по себе не подтверждает их identity.
Секреты и приватные ключи не копируются в tracked-документацию.

Первоначальная подготовка локальных release inputs и обычный offline
`ultra-install apply` для bootstrap описаны отдельно в [README](../README.md).
Эти процедуры не являются альтернативным upgrade-путём для production.

## PostgreSQL backup и restore

Операции с данными остаются отдельными инструментами для фактического DB
recovery или другой явно порученной операции. Backup/restore не запускается
обычным deploy, не является его prerequisite и не должен применяться поверх
здоровой primary. См. [DB recovery](../deploy/recovery/README.md) и
[контракт PostgreSQL](replication.md).

## Тематические инструкции

- [Политика полной замены production](production-replacement.md)
- [Перенос bridge при отдельной БД](bridge-migration.md)
- [DB replication, backup и tunnel](replication.md)
- [DNS и TLS входов](subscription-ingress.md)
- [Разработка и проверки](development.md)
