# Доступ по SSH-ключу к двум серверам (front и back)

Оркестратор (`make install`, `ultra-install`, `deploy/bootstrap-*.sh`) рассчитан на **вход без пароля**: `ssh -o BatchMode=yes` завершится ошибкой, если ключ не принят.

## 1. Сгенерировать ключ (на вашем ноутбуке или рабочей машине)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/ultra_relay_ed25519 -C "ultra-relay-deploy"
```

Парольную фразу (passphrase) можно задать для защиты файла ключа; тогда перед установкой запускайте агент:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/ultra_relay_ed25519
```

В `make install` / `ultra-install` поле пути к ключу можно оставить пустым, если ключ уже добавлен в агент.

## 2. Установить публичный ключ на **оба** сервера

Повторите для **front** (bridge) и **back** (exit), подставив пользователя (часто `root` или `ubuntu`) и IP/hostname.

### Вариант A: `ssh-copy-id` (если пока есть парольный вход)

```bash
ssh-copy-id -i ~/.ssh/ultra_relay_ed25519.pub root@FRONT_IP
ssh-copy-id -i ~/.ssh/ultra_relay_ed25519.pub root@BACK_IP
```

### Вариант B: вручную

На каждом сервере:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo 'ВСТАВЬТЕ_СОДЕРЖИМОЕ_ultra_relay_ed25519.pub' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Для `root` файл: `/root/.ssh/authorized_keys`. Для пользователя `ubuntu`: `/home/ubuntu/.ssh/authorized_keys`.

## 3. Проверить вход без пароля (как в CI/скриптах)

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i ~/.ssh/ultra_relay_ed25519 root@FRONT_IP 'echo ok'
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i ~/.ssh/ultra_relay_ed25519 root@BACK_IP 'echo ok'
```

Обе команды должны напечатать `ok` без запроса пароля.

## 4. Удобный `~/.ssh/config` (необязательно)

```sshconfig
Host ultra-front
  HostName FRONT_IP
  User root
  IdentityFile ~/.ssh/ultra_relay_ed25519

Host ultra-back
  HostName BACK_IP
  User root
  IdentityFile ~/.ssh/ultra_relay_ed25519
```

Тогда проверка: `ssh -o BatchMode=yes ultra-front 'echo ok'`.

## 5. Связка с установкой ultra

- **`make install`** — при запросе укажите тот же путь: `~/.ssh/ultra_relay_ed25519` или оставьте пустым при работающем `ssh-agent`.
- **`ultra-install -identity ~/.ssh/ultra_relay_ed25519`** — то же для прямого вызова.
- Если на серверах SSH слушает **нестандартный порт**, стандартные скрипты его не задают: используйте `~/.ssh/config` с директивой `Port` или обёртку `ProxyJump` и вызывайте команды вручную.

## 6. Ошибки

| Симптом | Что проверить |
|--------|----------------|
| `Permission denied (publickey)` | Ключ не в `authorized_keys`, неверный пользователь или путь `-i`. |
| `Host key verification failed` | Первый заход: скрипты используют `StrictHostKeyChecking=accept-new`; при смене ключа сервера очистите запись в `~/.ssh/known_hosts`. |
| `ubuntu@` не пускает в root | На VPS используйте пользователя с `sudo` и задайте его в `-ssh-user` / вопросе скрипта; убедитесь, что у него есть права на `systemctl` и запись в `/etc/ultra-relay`. |

Передавать **root-пароль** в `make install` или в репозиторий не нужно и небезопасно.
