# Переустановка non-DB production

Эта страница заменяет прежний runbook восстановления non-DB узлов. Используйте
только штатный [`make deploy`](production-replacement.md) для полной замены.
Для production deployment используйте только штатный путь полной замены,
описанный в [production replacement](production-replacement.md).

Старые non-DB серверы и связанные с ними deployment journals, markers и jobs
отбрасываются; старую операцию не возобновляют, не откатывают и не согласуют.
PostgreSQL primary, прикладные таблицы, данные и версия миграций сохраняются.
Обычная замена не выполняет dump, restore, import или migration прикладной БД;
она может восстановить служебные объекты `ultra_monitor` для replica status.
Аварийные DB backup/restore-процедуры
описаны отдельно в [DB recovery](../deploy/recovery/README.md).
