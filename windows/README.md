# Nadejda для Windows

Windows-версия Nadejda обходит DPI тем же способом, что и Linux-версия:
разрезает TLS ClientHello, подмешивает фейковый пакет с низким TTL и/или
перекрывает последовательность (seqovl). Отличается только транспорт:

| | Linux | Windows |
|---|---|---|
| перехват | nftables → NFQUEUE | WinDivert |
| инъекция | raw socket с fwmark | `WinDivertSend` |
| автозапуск | systemd | планировщик заданий |
| DNS-прокси | есть | нет (системный DNS не трогаем) |

Логика стратегий (`nadejda/desync.py`, `nadejda/packet.py`) общая, поэтому
списки доменов, пресеты и `[overrides]` работают одинаково.

## Требования

- Windows 10/11 x64.
- Python 3.11 или новее (при установке отметьте **Add python.exe to PATH**).
- Права администратора — WinDivert устанавливает драйвер и перехватывает
  пакеты только с повышенными правами.

## Установка

Откройте PowerShell **от имени администратора** в папке репозитория:

```powershell
powershell -ExecutionPolicy Bypass -File windows\install.ps1
```

Установщик:

1. копирует программу в `C:\ProgramData\Nadejda\app`;
2. создаёт виртуальное окружение `C:\ProgramData\Nadejda\venv` и ставит
   `pydivert` (внутри — подписанный драйвер WinDivert);
3. устанавливает команду `nadejda-win`;
4. кладёт конфиг в `C:\ProgramData\Nadejda\config.toml` (существующий не
   перезаписывает, новые умолчания пишет в `config.toml.new`);
5. регистрирует задачу планировщика **Nadejda** — запуск при входе в систему
   с правами администратора, без запроса UAC;
6. добавляет ярлыки в меню «Пуск».

Сразу запустить:

```powershell
powershell -ExecutionPolicy Bypass -File windows\install.ps1 -Start
```

Без задачи автозапуска (только файлы и команда):

```powershell
powershell -ExecutionPolicy Bypass -File windows\install.ps1 -NoTask
```

## Запуск и остановка

Из терминала **от имени администратора**:

```powershell
nadejda-win start
```

Или без открытия терминала и без UAC — через задачу планировщика:

```powershell
schtasks /Run /TN Nadejda
```

Остановить:

```powershell
nadejda-win stop
```

Если `nadejda-win` не находится, откройте новое окно терминала (установщик
добавил `C:\ProgramData\Nadejda\venv\Scripts` в пользовательский `PATH`) или
запускайте напрямую:

```powershell
& "$env:ProgramData\Nadejda\venv\Scripts\nadejda-win.exe" status
```

Разовый запуск с повышением прав из репозитория:

```cmd
windows\start-nadejda.cmd
```

## Команды

```text
nadejda-win start [--config PATH] [--strategy NAME] [--udp-strategy NAME]
nadejda-win stop
nadejda-win status
nadejda-win test
nadejda-win doctor
nadejda-win gui
nadejda-win config
```

- `test` — проверяет, что WinDivert доступен, фильтр корректен, а каждая
  стратегия (глобальная и все `[overrides]`) действительно перестраивает
  ClientHello, сохраняя все его байты. Отдельно проверяются QUIC и голос
  Discord. Запускайте после установки и после правки конфига.
- `doctor` — версия Python, pydivert, права, путь к конфигу, фильтр.
- `status` — счётчики работающего движка (пакеты, desync, UDP, ошибки).
- `gui` — графический интерфейс на tkinter: выбор стратегии, старт/стоп,
  счётчики и лог. Если окно открыто без прав администратора, кнопка
  **Run as administrator** перезапускает его с одним запросом UAC.

## Конфигурация

`C:\ProgramData\Nadejda\config.toml` — тот же формат, что и на Linux:

```toml
[desync]
strategy = "seqovl568"

[overrides]
"youtube.com" = "fake_split_goodsum_ttl3_disorder"
"googlevideo.com" = "split_sni"

[general]
quic = "desync"          # desync | block | off
sni_filter = true
tcp_ports = [80, 443, 2053, 2083, 2087, 2096, 8443]
udp_voice_ports = ["19294-19344", "50000-50100"]
```

После правки перезапустите движок:

```powershell
nadejda-win stop
schtasks /Run /TN Nadejda
```

Проверить, что стратегия подходит именно вашему провайдеру, можно по логу
`C:\ProgramData\Nadejda\nadejda.log` и счётчикам `nadejda-win status`.
Автоподбор (`autotune`) пока реализован только для Linux — на Windows
перебирайте пресеты вручную через `--strategy` или в GUI.

## Чем Windows-версия отличается

- **Нет DNS-прокси.** Linux-версия перехватывает DNS через nftables; на
  Windows системный резолвер не трогается. Для обхода по SNI это не нужно,
  поэтому `dns`, `dns_port`, `dns_upstreams` и `dns_strip_aaaa` игнорируются.
- **Нет адресных наборов и `scope`.** На Linux `scope = "list"` ограничивает
  правила адресами из резолвера; на Windows фильтр WinDivert работает по
  портам, а список доменов применяется по SNI (`sni_filter`, встроенные
  списки и `extra_domains`).
- **Нет `stall_reset`.** Движок видит только исходящие пакеты и не может
  определить, что сервер молчит; сброс «зависших» сокетов остаётся
  Linux-функцией. Разрезанный ClientHello, потерявший сегмент, просто
  отбрасывается — клиент переотправит его.
- **Game Filter** поддерживается фильтром WinDivert, но по умолчанию выключен,
  как и на Linux.
- **WinDivert вместо raw-сокетов** означает, что антивирус может показать
  предупреждение о драйвере. Драйвер WinDivert подписан и используется многими
  легальными программами (в том числе zapret/GoodbyeDPI); добавьте папку
  `C:\ProgramData\Nadejda` в исключения, если антивирус её блокирует.

## Удаление

```powershell
powershell -ExecutionPolicy Bypass -File windows\install.ps1 -Uninstall
```

Удаляются задача планировщика, ярлыки, `app`, `venv` и запись в `PATH`.
Конфиг сохраняется; чтобы удалить и его, добавьте `-RemoveConfig`.

## Если не работает

1. `nadejda-win doctor` — проверьте `pydivert`, `administrator: True` и
   `filter check: ok`.
2. `nadejda-win test` — если падает проверка стратегии, значит выбранный
   пресет не подходит; попробуйте другой:
   `nadejda-win start --strategy fake_split_goodsum_ttl3_disorder`.
3. Лог: `C:\ProgramData\Nadejda\nadejda.log`.
4. «Access is denied» / «cannot open WinDivert» — запустите от администратора
   или используйте `schtasks /Run /TN Nadejda`.
5. Сайт открывается, но видео/голос тормозит — проверьте `quic = "desync"` и
   диапазоны `udp_voice_ports`.

## Безопасность

Nadejda не отправляет трафик через чужие серверы и не расшифровывает TLS:
пакеты перестраиваются локально. Прокси для Telegram и подобные сервисы —
отдельная настройка, к этому движку она не относится.
