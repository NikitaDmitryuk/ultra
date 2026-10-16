"""Unit tests plus opt-in isolated PostgreSQL transaction regression.

Run integration explicitly: python3 test_dump_exit_identity.py --test-dsn <isolated-test-DSN>
Never discovers a DSN from the environment. The fixture uses an exclusive temporary
schema and rewrites only the helper's public qualification for that schema.
"""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

SPEC = importlib.util.spec_from_file_location('dump_identity', Path(__file__).parents[1] / 'ansible/library/ultra_dump_exit_identity.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
DSN = None
if '--test-dsn' in sys.argv:
    index = sys.argv.index('--test-dsn')
    DSN = sys.argv[index + 1]
    del sys.argv[index:index + 2]


def receipt():
    return {'database': 'ultra', 'user': 'ultra', 'sha256': 'a' * 64,
            'system_identifier': '123', 'database_oid': '42'}


def route():
    return {'address': '203.0.113.10', 'port': 443,
            'tunnel_uuid': '11111111-1111-4111-8111-111111111111',
            'pinned_peer_cert_sha256': 'b' * 64}


class InputTests(unittest.TestCase):
    def value(self, entries=None, policy='pin', recorded=None):
        return helper.payload('ultra', 'ultra', 'a' * 64, entries or [route()], policy, recorded or receipt())

    def test_binding_covers_archive_route_pin_and_tls_policy(self):
        original = self.value()['binding']
        for field, value in [('address', '203.0.113.11'), ('port', 8443),
                             ('tunnel_uuid', str(uuid.uuid4())), ('pinned_peer_cert_sha256', 'c' * 64)]:
            item = route()
            item[field] = value
            self.assertNotEqual(original, self.value([item])['binding'])
        self.assertNotEqual(original, self.value(policy='ca')['binding'])
        self.assertEqual(self.value(), self.value())

    def test_ca_policy_clears_old_leaf_pin(self):
        self.assertEqual(self.value(policy='ca')['routes'][0]['pin'], '')

    def test_receipt_mismatch_rejected_before_call(self):
        changed = receipt()
        changed['sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'receipt_mismatch'):
            self.value(recorded=changed)

    def test_duplicate_endpoints_and_unverified_pins_rejected(self):
        with self.assertRaises(ValueError):
            self.value([route(), route()])
        item = route()
        item['pinned_peer_cert_sha256'] = ''
        with self.assertRaises(ValueError):
            self.value([item])

    def test_psql_uses_one_transaction_and_no_sensitive_argv(self):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout='\ntrue\n')
        self.assertTrue(helper.reconcile('ultra', 'ultra', 'secret', 'a' * 64, [route()], 'pin', receipt, run))
        argv, options = calls[0]
        self.assertNotIn('secret', argv)
        self.assertEqual(options['env']['PGPASSWORD'], 'secret')
        self.assertTrue(options['input'].startswith('BEGIN;'))
        self.assertTrue(options['input'].endswith('COMMIT;\n'))
        self.assertIn('LOCK TABLE public.exit_nodes', options['input'])
        self.assertNotIn(route()['address'], options['input'])


@unittest.skipUnless(DSN, 'requires explicit --test-dsn for an isolated test database')
class PostgresTests(unittest.TestCase):
    def sql(self, query, success=True):
        result = subprocess.run(['psql', DSN, '-XAtq', '-v', 'ON_ERROR_STOP=1'], input=query,
                                text=True, capture_output=True, timeout=30)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result.stdout.strip()

    def setUp(self):
        self.schema = 'dump_identity_test_' + uuid.uuid4().hex
        self.sql('CREATE SCHEMA ' + self.schema)
        self.addCleanup(lambda: self.sql('DROP SCHEMA ' + self.schema + ' CASCADE'))
        self.sql('''CREATE TABLE %s.exit_nodes (
          id uuid PRIMARY KEY, address text, port int, tunnel_uuid text UNIQUE,
          pinned_peer_cert_sha256 text, enabled boolean, budget bigint, usage bigint,
          name text, metadata jsonb, updated_at timestamptz);
          INSERT INTO %s.exit_nodes VALUES
          ('22222222-2222-4222-8222-222222222222','203.0.113.10',443,'old','old-pin',true,500,123,'kept','{"member":"kept"}','2020-01-01'),
          ('33333333-3333-4333-8333-333333333333','203.0.113.11',443,'other','other-pin',true,700,456,'other','{}','2020-01-02');
          CREATE TABLE %s.users(id int, balance bigint);
          INSERT INTO %s.users VALUES(1,99);''' % ((self.schema,) * 4))
        actual = self.sql("SELECT current_database(), (SELECT system_identifier FROM pg_control_system()), (SELECT oid FROM pg_database WHERE datname=current_database())")
        database, system, oid = actual.split('|')
        self.recorded = receipt()
        self.recorded.update(database=database, system_identifier=system, database_oid=oid)
        self.database = database

    def value(self, entries=None, policy='pin'):
        return helper.payload(self.database, 'ultra', 'a' * 64, entries or [route()], policy, self.recorded)

    def apply(self, value=None, success=True):
        return self.sql(helper.statement(value or self.value()).replace('public.', self.schema + '.'), success)

    def snapshot(self):
        return self.sql('SELECT row_to_json(n) FROM %s.exit_nodes n ORDER BY id; SELECT row_to_json(u) FROM %s.users u' % (self.schema, self.schema))

    def test_preserves_data_and_idempotent_retry(self):
        before = self.snapshot().splitlines()
        self.assertEqual(self.apply().splitlines()[-1], 'true')
        after = self.snapshot().splitlines()
        expected = json.loads(before[0])
        expected.update(tunnel_uuid=route()['tunnel_uuid'], pinned_peer_cert_sha256=route()['pinned_peer_cert_sha256'])
        self.assertEqual(json.loads(after[0]), expected)
        self.assertEqual(after[1:], before[1:])
        self.assertEqual(self.apply().splitlines()[-1], 'false')
        self.assertEqual(self.snapshot().splitlines(), after)

    def test_missing_and_ambiguous_mapping_roll_back(self):
        before = self.snapshot()
        missing = route()
        missing['address'] = '203.0.113.99'
        missing['tunnel_uuid'] = str(uuid.uuid4())
        self.apply(self.value([route(), missing]), success=False)
        self.assertEqual(self.snapshot(), before)
        self.sql("INSERT INTO %s.exit_nodes(id,address,port,tunnel_uuid) VALUES('%s','203.0.113.10',443,'duplicate')" % (self.schema, uuid.uuid4()))
        before = self.snapshot()
        self.apply(success=False)
        self.assertEqual(self.snapshot(), before)

    def test_fresh_identity_update_requires_same_membership(self):
        self.apply()
        before = self.snapshot().splitlines()
        modified = route()
        modified['tunnel_uuid'] = '44444444-4444-4444-8444-444444444444'
        modified['pinned_peer_cert_sha256'] = 'c' * 64
        self.assertEqual(self.apply(self.value([modified])).splitlines()[-1], 'true')
        after = self.snapshot().splitlines()
        current = json.loads(after[0])
        self.assertEqual(current['tunnel_uuid'], modified['tunnel_uuid'])
        self.assertEqual(current['pinned_peer_cert_sha256'], modified['pinned_peer_cert_sha256'])
        self.assertEqual(after[1:], before[1:])
        self.assertEqual(self.apply(self.value([modified])).splitlines()[-1], 'false')

        self.sql("UPDATE %s.exit_nodes SET tunnel_uuid='tampered' WHERE address='203.0.113.10'" % self.schema)
        before = self.snapshot()
        self.apply(self.value([modified]), success=False)
        self.assertEqual(self.snapshot(), before)

    def test_changed_route_membership_fails_closed(self):
        self.apply()
        changed = route()
        changed['address'] = '203.0.113.11'
        changed['tunnel_uuid'] = '44444444-4444-4444-8444-444444444444'
        before = self.snapshot()
        self.apply(self.value([changm���-�G����ƭyприкладную роль и БД, затем импортирует одной транзакцией. Действующую
непустую БД импорт не перезаписывает; повтор принимает только квитанцию,
связанную с архивом, идентификатором кластера и OID БД. Временный upload удаляется.
Поле предназначено для свежего bootstrap с `REUSE_BRIDGE_SPEC=false`; без него
создаётся чистая БД. Relay применяет миграции перед обслуживанием запросов.

Если дамп задан, имеющийся в нём месячный бюджет статического выхода остаётся
источником истины и расход не обнуляется. Конфигурация может не дублировать
бюджет. Если в восстановленной БД для настроенного выхода бюджета нет, настройка
статических бюджетов завершится ошибкой; для установки без дампа бюджет нужно
задать явно в `ULTRA_AUTOMATION_STATIC_NODES`.

Для установки всех узлов с нуля используйте `ultra-install apply --config
install.config`, а не `make deploy`: последний выполняет ручной upgrade/adoption.
До `apply` локально подготовьте все входы из конфигурации:

1. Соберите release-комплект (`make release-dist`) и укажите абсолютный путь к
   его каталогу и точную версию из `release-manifest.json` в канонической паре
   `ULTRA_AUTOMATION_RELEASE_DIR` / `ULTRA_AUTOMATION_VERSION`.
2. Создайте файл `known_hosts` с ключами всех трёх чистых серверов, проверенными
   через доверенный интерфейс провайдера. `ssh-keyscan` сам по себе не доказывает
   подлинность ключей. Укажите существующий локальный путь в
   `ULTRA_AUTOMATION_KNOWN_HOSTS_FILE`.
3. Установите локальный `pg_restore`; файл дампа должен быть приватным, в формате
   custom и проходить `pg_restore --list`.
   Подготовка offline Ansible runtime использует операторский `TMPDIR`; при
   ограниченной квоте системного `/tmp` задайте доступный каталог с достаточным
   свободным местом.
4. Проверьте DNS-записи и наличие нужных секретов в `.env`, затем выполните
   `ultra-install doctor --config install.config`. `doctor` безопасен и не
   подключается к серверам без сетевого режима.

`doctor` и локальная валидация не проверяют готовность внешнего backup target,
DNS propagation, выпуск сертификата или реальный VPN-трафик. Полная bootstrap
приёмка требует доставленной свежей копии на узел другого provider. Provider в
статической политике должен отличать реальные независимые домены отказа, а не
быть произвольной меткой.

При восстановлении непустого `exit_nodes` из дампа identity маршрута должна быть
согласована с новыми exit до активации bridge. Bootstrap разрешает привязать новые
tunnel UUID и TLS pins только к тем же включённым строкам, однозначно найденным
по IP и порту. Если endpoint-набор или соответствие строк изменились, активация
останавливается. Сама таблица, членство, пользователи и прочие поля при этом не
перезаписываются. Сохранение и согласование БД не подтверждают работоспособность
VPN после переустановки узлов: всё равно требуется проверить реальный трафик.

Служебный ключ bridge → exit хранится отдельно от операторских ключей:
`/etc/ultra-fleet` принадлежит root, имеет группу ultra-relay и права 0750;
сам ключ принадлежит ultra-relay с правами 0600. Резервная копия сохраняет
ключ и публичную часть, а восстановление возвращает права родительского каталога.
