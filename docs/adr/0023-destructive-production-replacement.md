# 0023 — Полная замена production с сохранением PostgreSQL

## Статус

accepted

## Дата

2026-10-23

## Контекст

Пользователь выбрал предсказуемый штатный путь возвращения VPN после неудачной
выкладки: полную замену non-DB окружения без восстановления старой операции.
Production PostgreSQL и пользовательские данные должны оставаться на месте.

## Решение

`make deploy` является единственным штатным путём по умолчанию для полной замены
non-DB production. Старые bridge/exit runtime и вся связанная с прежней
выкладкой metadata (journals, markers, jobs, receipts) отбрасываются. Их не
возобновляют, не откатывают и не пытаются reconcile с новой установкой.

PostgreSQL primary и её схема сохраняются без изменений. Deploy фиксирует
primary identity и schema до замены и сверяет их после неё. Обычная замена не
создаёт dump и не выполняет restore, import или migration. DB host не входит в
набор заменяемых узлов. Для deploy не требуются предоставленный оператором
backup, backup digest, restore receipt или дополнительный ACK. Отдельные DB
backup/restore-инструменты сохраняются для явно порученного аварийного
восстановления или операции с данными и не являются gate для VPN deploy.

Bootstrap/recovery automation вспомогательна и не должна блокировать обычную
VPN-замену. Core deployment включает VPN relay, ingress и bot. Пользовательские
функции приложения, включая Mini App и cloud lifecycle, сохраняются.

## Рассмотренные альтернативы

- Resume, rollback и reconciliation старой deployment operation — отклонены:
  штатная модель заменяет non-DB runtime целиком.
- Включение DB dump/restore/import/migration в каждый deploy — отклонено:
  обычная замена не должна менять PostgreSQL или требовать операции с данными.
- Обязательный operator backup, receipt или ACK для routine deploy — отклонён:
  primary identity/schema проверяются напрямую до и после замены.
- Обязательное ожидание recovery/bootstrap automation — отклонено: эти средства
  не являются зависимостью доступности VPN.

## Последствия

Полный простой и потеря состояния non-DB узлов приемлемы. DB recovery остаётся
отдельным инструментом. Обычный deploy должен оставлять primary и схему без
изменений; identity/schema проверяются до и после, а любое изменение схемы
требует отдельной явно спланированной операции.

## Источники

[Политика полной замены](../production-replacement.md),
[операторская автоматизация](../automation.md),
[DB recovery](../../deploy/recovery/README.md),
пользовательское решение от 2026-10-23.
