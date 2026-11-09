# Nadejda

**Nadejda** — обход DPI-блокировок на Linux. Это самостоятельная реализация в духе
zapret: свой движок на Python (только стандартная библиотека), свой клиент NFQUEUE
поверх netlink и собственные стратегии рассинхронизации TCP **и UDP/QUIC**. Это
**не** обёртка над `nfqws` и не требует `libnetfilter_queue`.

Цель — вернуть доступ к **GitHub, YouTube, Spotify, SoundCloud, ChatGPT и Discord**
на сетях, где провайдер фильтрует TLS по SNI, подменяет DNS и режет QUIC.

---

## Как это работает

```
                     ┌──────────────────────────────────────────────┐
 приложение ──TCP──▶ │ nftables, hook output, priority -150         │
        └──UDP/QUIC──▶│  • DNS :53  → redirect на локальный прокси   │
                     │  • UDP :443 → queue (фрагментация QUIC)      │
                     │  • TCP :443 → queue num 200 bypass           │
                     └───────────────────┬──────────────────────────┘
                                         │ NFQUEUE (netlink)
                                         ▼
                     ┌──────────────────────────────────────────────┐
                     │ движок Nadejda                               │
                     │  TCP: ClientHello, SNI, split/seqovl/fake    │
                     │  UDP: QUIC Initial → IP-фрагменты            │
                     │  отправка пакетов через raw-сокет            │
                     └───────────────────┬──────────────────────────┘
                                         │ SO_MARK 0x4E414445
                                         ▼
                                    сеть / сервер
```

1. Правило nftables отправляет исходящие TCP-пакеты и QUIC-датаграммы на порт
   443 в NFQUEUE.
2. Движок разбирает TLS ClientHello, достаёт SNI и решает, трогать ли соединение.
   Поддельный ClientHello для прикрытия использует SNI `ya.ru`, а не Google:
   Google/YouTube во многих сетях троттлят так же, и тогда прикрытие не помогает.
3. TCP: вместо исходного пакета отправляются подготовленные сегменты —
   разрезанные, с перекрытием sequence number, с поддельным ClientHello и малым
   TTL или фрагментированные на уровне IP. DPI видит одно, сервер собирает другое.
   UDP/QUIC: движок распознаёт Initial-пакеты и режет датаграмму на IP-фрагменты.
   Конечная точка собирает её обратно, а DPI, который не занимается реассемблингом,
   видит только обрезанный первый фрагмент. Не-QUIC UDP (TURN/RTP, голос Discord)
   проходит без изменений.
4. Для части Google/YouTube адресов QUIC принудительно отклоняется: провайдер
   режет его глубже фрагментации, поэтому браузер мгновенно уходит на TCP, где
   работает обычная стратегия. Список задаётся в `[udp] force_tcp_domains`.
5. Все пакеты самого Nadejda помечаются `SO_MARK`, а правило
   `meta mark 0x4e414445 return` не пускает их обратно в очередь — поэтому
   повторной обработки и петель нет.
6. Отдельный локальный DNS-прокси ходит в DNS-over-TLS (1.1.1.1 / 8.8.8.8 /
   9.9.9.9) и перехватывает порт 53 отдельной nat-цепочкой nftables.
   `/etc/resolv.conf` не изменяется, поэтому подмена DNS провайдером перестаёт
   влиять на браузер.

### Чего Nadejda не делает

* Не шифрует и не «прячет» ваш трафик — это не VPN. IP-адрес остаётся вашим.
* Не обходит блокировки на уровне IP-адресов и серверные гео-ограничения.
* Не помогает, если провайдер блокирует UDP целиком, а не только QUIC: тогда
  остаётся TCP-обход (или VPN).

---

## Требования

| Компонент | Требование |
|---|---|
| ОС | Linux с nftables и NFQUEUE (`nfnetlink_queue`) |
| Python | 3.11+ (нужен `tomllib`), сторонние пакеты не нужны |
| Права | root / `CAP_NET_ADMIN` + `CAP_NET_RAW` |
| Пакеты | `nftables`, `util-linux` (для тестов), `python` |

Проверено на Arch Linux, ядро 7.x, Python 3.14. Подойдёт любой современный
дистрибутив с nftables (Debian/Ubuntu/Fedora/OpenWrt с Python).

---

## Скачать и установить

Нужен Linux с nftables и NFQUEUE, Python 3.11+ и права root. Сторонние
Python-пакеты не требуются.

### Вариант 1 — git (рекомендуется)

```bash
git clone https://github.com/mastervor4070-cell/Nadejda.git
cd Nadejda
sudo ./install.sh
```

Обновление в будущем:

```bash
cd Nadejda
git pull
sudo ./install.sh
```

### Вариант 2 — ZIP с GitHub

1. Откройте страницу репозитория: <https://github.com/mastervor4070-cell/Nadejda>.
2. Нажмите зелёную кнопку **Code → Download ZIP**.
3. Распакуйте архив и запустите установщик:

```bash
unzip Nadejda-main.zip
cd Nadejda-main
sudo ./install.sh
```

### Вариант 3 — tar.gz из GitHub

```bash
curl -L -o Nadejda.tar.gz \
  https://github.com/mastervor4070-cell/Nadejda/archive/refs/heads/main.tar.gz
tar -xzf Nadejda.tar.gz
cd Nadejda-main
sudo ./install.sh
```

### Что делает установщик

Установщик:

* **останавливает и отключает zapret/byedpi** (`nfqws`, `ciadpi`, сервисы
  `zapret*`, `byedpi*`) и удаляет их оставшиеся таблицы nftables — они делят
  с Nadejda один и тот же NFQUEUE;
* копирует программу в `/opt/nadejda`;
* создаёт запускалки `/usr/local/bin/nadejda` и `/usr/local/bin/nadejda-gui`;
* ставит иконку и ярлык в меню приложений
  (`/usr/share/icons/hicolor/scalable/apps/nadejda.svg`,
  `/usr/share/applications/io.github.nadejda.Nadejda.desktop`);
* ставит конфиг в `/etc/nadejda/config.toml` (существующий не перезаписывает,
  новые значения кладёт рядом как `config.toml.new`);
* ставит и включает `systemd/nadejda.service` (автозапуск при загрузке,
  но сразу не запускает — сначала стоит подобрать стратегию).

Полезные варианты:

```bash
sudo ./install.sh --start        # установить и сразу запустить
sudo ./install.sh --no-systemd   # только файлы, без systemd
sudo ./install.sh --keep-zapret  # не трогать zapret/byedpi
sudo ./install.sh --uninstall    # удалить (конфиг сохраняется)
```

Если zapret был установлен раньше и вы не хотите его удалять, но он мешает
запуску, остановите его отдельно:

```bash
sudo nadejda stop-zapret           # остановить, отключить автозапуск, убрать nft
sudo nadejda stop-zapret --dry-run # только показать, что будет сделано
```

---

## Быстрый старт

```bash
# 1. Проверить окружение (python, nft, модули ядра, DoT, конкурирующие процессы)
sudo nadejda doctor

# 2. Подобрать рабочую стратегию под вашего провайдера и сохранить её
sudo nadejda autotune --quick --save

# 3. Запустить
sudo systemctl start nadejda        # или: sudo nadejda start

# 4. Проверить доступность сайтов
nadejda test

# 5. Диагностика
nadejda status
nadejda logs -n 50
```

Если `autotune` не нашёл ни одной рабочей стратегии и все проверки падают,
скорее всего блокировка не по SNI: это IP-блок или серверное гео-ограничение —
тут нужен VPN/прокси, DPI-обход не поможет.

Если сайты открываются, но ответ обрывается на 5–20 КБ, запустите второй этап:

```bash
sudo nadejda autotune --fine --save --service
```

Он перебирает TTL поддельного пакета (2–5), число повторов, паузу и точку
разреза вокруг найденной стратегии и выбирает самый стабильный вариант.

---

## Графическое приложение

После установки Nadejda появляется в меню приложений как **Nadejda** (иконка
щита с молнией). Запуск из меню или из терминала:

```bash
nadejda-gui
# то же самое: nadejda gui
```

Приложение написано на GTK4 + libadwaita и работает от обычного пользователя.
Всё, что требует root (запуск/остановка службы, автоподбор, сохранение
конфига), выполняется через `pkexec`, если запущен агент polkit. Если агента
нет (частый случай на Hyprland/sway), GUI поднимает его сам, а при неудаче
показывает обычное окно ввода пароля через `sudo -A` и `zenity`/`kdialog` —
пароль спрашивается один раз в графическом окне, терминал не нужен.

Что есть в окне:

* **Главная** — большая карточка состояния с переключателем «работает /
  выключена», кнопки «Проверить сайты» (TLS-проверка GitHub, YouTube, Spotify,
  SoundCloud, ChatGPT, Discord с результатом по каждому хосту),
  «Автоподбор» (перебор стратегий с сохранением лучшей) и «Журнал».
* **Настройки** — TCP-стратегия, UDP/QUIC-стратегия, режим QUIC
  (`desync` / `block` / `off`), область обработки (`all` / `list`), фильтр по
  SNI и DNS-over-TLS. Изменения пишутся в `/etc/nadejda/config.toml`
  с сохранением комментариев; если служба запущена, она перезапускается
  автоматически.
* **Журнал** — последние строки `/var/log/nadejda.log` с автообновлением.

Для GUI нужны пакеты `python-gobject`, `gtk4`, `libadwaita` (Arch) или
`python3-gi`, `gir1.2-gtk-4.0`, `gir1.2-adw-1` (Debian/Ubuntu). Без них
CLI продолжает работать как обычно.

---

## Команды

| Команда | Что делает |
|---|---|
| `nadejda start [-f]` | запустить движок (в фоне; `-f` — на переднем плане) |
| `nadejda stop` | остановить и убрать правила nftables |
| `nadejda restart` | перезапуск |
| `nadejda status` | состояние, стратегия, очередь, DNS |
| `nadejda test [хосты…]` | TLS-проверка сайтов (по умолчанию все целевые) |
| `nadejda autotune [--quick] [--fine] [--only S] [--save]` | перебрать стратегии и выбрать лучшую |
| `nadejda doctor` | диагностика окружения |
| `nadejda update-lists` | обновить IP-наборы (для `scope="list"`) |
| `nadejda autotune --service` | автоподбор с остановкой/запуском systemd-службы |
| `nadejda gui` | графический интерфейс (то же, что `nadejda-gui`) |
| `nadejda stop-zapret [--dry-run]` | остановить и отключить zapret/byedpi |
| `nadejda set-config [--strategy S] [--udp-strategy S] [--quic desync\|block\|off] [--scope all\|list] [--dns/--no-dns] [--override D=S] [--clear-overrides] [--restart]` | изменить конфиг, сохранив комментарии |
| `nadejda logs [-n N]` | последние строки `/var/log/nadejda.log` |
| `nadejda config [--write-default]` | путь к конфигу / записать дефолтный |

Глобальные опции: `--config PATH`, `-v` (подробный лог).

`nadejda test`, `status`, `logs` и `doctor` работают и без root
(без root нельзя менять nftables).

---

## Конфигурация

Файл: `/etc/nadejda/config.toml` (полный список с комментариями — в
[`config/config.toml`](config/config.toml)).

Самое важное:

```toml
[general]
scope = "all"          # "all" — все адреса, "list" — только из списка хостов
sni_filter = true      # трогать только ClientHello с известным SNI
quic = "desync"        # "desync" | "block" | "off"
dns = true             # локальный DNS-over-TLS прокси
dns_port = 5353
dns_strip_aaaa = false # true — вырезать IPv6-ответы
stall_reset = true     # сбрасывать потоки, которые провайдер «зачернил»

# Порты как в zapret. 2053/2083/2087/2096/8443 — Discord media.
tcp_ports = [80, 443, 2053, 2083, 2087, 2096, 8443]
# Голос и демонстрация экрана Discord: перед каждым пакетом идёт fake.
udp_voice_ports = ["19294-19344", "50000-50100"]
# Аналог --dpi-desync-cutoff (голос обрабатывается без cutoff).
tcp_cutoff = 4
udp_cutoff = 6
# Game Filter как в zapret; по умолчанию выключен.
game_filter = "off"    # "off" | "tcp" | "udp" | "all"
game_tcp_ports = "1024-65535"
game_udp_ports = "1024-65535"

refresh_seconds = 900
log_level = "info"

[desync]
strategy = "zapret_general"   # профиль из general.bat zapret
positions = "1"
seqovl = 568
seqovl_pattern = "tls_4pda"   # настоящий ClientHello 4PDA из zapret
cutoff = 4

[udp]
strategy = "quic_frag"  # quic_frag | zapret_quic | quic_off | ...
split = 64              # байт QUIC-нагрузки в первом IP-фрагменте
disorder = true         # хвостовые фрагменты отправляются первыми
fake_payload = "quic_google"  # блоб для режима fake (zapret_quic)
voice_payload = "discord_udp" # блоб для голоса/экрана Discord
force_tcp_domains = [   # для них QUIC отклоняется → быстрый откат на TCP
  "youtube.com", "googlevideo.com", "youtu.be", "ytimg.com",
]
```

`block_quic` — устаревший синоним; если в конфиге есть `quic`, он игнорируется.

После правки: `sudo nadejda restart` (или `sudo systemctl restart nadejda`).

### Совместимость с zapret-discord-youtube

Nadejda повторяет основные профили и область действия
[Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
(движок при этом свой, не обёртка над `nfqws`):

* **Порты TCP**: `80, 443, 2053, 2083, 2087, 2096, 8443` — как
  `--wf-tcp` в `general.bat`.
* **UDP**: QUIC на `443` и диапазоны голоса/экрана Discord
  `19294-19344`, `50000-50100` — как `--wf-udp`.
* **Game Filter**: `game_filter = "off" | "tcp" | "udp" | "all"` и
  диапазоны `game_tcp_ports` / `game_udp_ports` (по умолчанию
  `1024-65535`). Выключен, как и в zapret; включайте только если игры
  действительно режутся.
* **Cutoff**: nftables пропускает в userspace только первые
  `tcp_cutoff + 12` пакетов потока (SYN, ACK, сегменты большого
  ClientHello и наши собственные инжектированные пакеты тоже считаются),
  поэтому большие загрузки не идут через Python. Аналог
  `--dpi-desync-cutoff`.
* **Пересборка ClientHello**: реальный Chrome/OpenSSL ClientHello
  (~1.5 КБ) не влезает в один TCP-сегмент. Nadejda буферизует оба
  сегмента и десинхронизирует целую запись; частичный фрагмент
  отбрасывается, чтобы SNI не утёк к DPI. Данные после рукопожатия
  десинхронизируются только один раз и только если перекрытие целиком
  лежит в уже подтверждённом ClientHello — иначе шаблон мог бы попасть
  в ещё не доставленные байты и сломать TLS.
* **Исключения**: `[hosts] exclude` — список доменов, которые нельзя
  трогать (банки, госуслуги, Steam/Epic, обновления ПО). По умолчанию
  там уже лежит безопасный стартовый набор.
* **Голос Discord**: для UDP-портов голоса и демонстрации экрана перед
  каждым настоящим датаграмом отправляется 3 поддельных
  `ACTIVE_DISCORD_UDP` с исходным TTL и валидной контрольной суммой —
  как в `general.bat` zapret. Битая сумма не годится: домашний NAT с
  `nf_conntrack_checksum=1` отбрасывает такие пакеты раньше, чем их
  увидит DPI, а TTL 3 может умереть до DPI провайдера. Фейки и настоящий
  пакет уходят синхронно и строго по порядку, поэтому DPI не видит
  настоящий Discord-пакет первым, а асинхронная очередь не добавляет
  джиттер. Cutoff на эти порты не распространяется — иначе длинная
  демонстрация экрана теряла
  бы защиту после первых пакетов. Это работает в режиме `quic_frag`, при
  `quic = "off"` и даже при стратегии `quic_off`. STUN/TURN на UDP/443
  не фрагментируется и не подделывается — иначе экран становится чёрным.
* **QUIC**: `zapret_quic` — поддельный Google QUIC Initial перед
  настоящим, как `--dpi-desync=fake` в zapret.

Профили TCP, перенесённые из `general.bat` / `general (ALT).bat`:

| Имя | Что делает |
|---|---|
| `zapret_general` | multisplit, разрез после 1-го байта, перекрытие 568 байт ClientHello 4PDA |
| `zapret_google` | перекрытие 681 байт Google ClientHello + `ip-id=0` |
| `zapret_discord` | как `zapret_google`, без `ip-id=0` (Discord media) |
| `zapret_fake` | fake + seqovl, 6 повторов, TTL 3, битая контрольная сумма |
| `zapret_fake_fakedsplit` | fake со STUN-блобом + seqovl |

Блобы (`tls_4pda`, `tls_google`, `quic_google`, `discord_udp`, `game_udp`)
взяты из MIT-лицензированного репозитория Flowseal (оригинал — bol-van/zapret)
и встроены в `nadejda/payloads.py`, поэтому установка не требует интернета.

Честные ограничения:

* это не побайтовый порт `nfqws`: часть тонких режимов (`fakedsplit`,
  `ts`-fooling, `ipset`) реализована упрощённо;
* провайдерский DPI иногда режет конкретный поток случайно — помогает
  новый 4-tuple (переподключение), а не смена стратегии;
* если игра/приложение использует собственный UDP-протокол вне
  перечисленных портов, нужен `game_filter`.

### Своя стратегия для отдельных доменов

Иногда глобальная стратегия оптимальна для CDN, но не пробивает конкретный
сайт, который провайдер рвёт по SNI. Для этого есть таблица `[overrides]`:

```toml
[overrides]
# ключ — домен; покрывает и все поддомены (api-v2.soundcloud.com и т.д.)
"soundcloud.com"    = "fake_split_goodsum_ttl3_disorder"
"soundcloud.cloud"  = "fake_split_goodsum_ttl3_disorder"
"sndcdn.com"        = "fake_split_goodsum_ttl3_disorder"
"youtube.com"       = "fake_split_goodsum_ttl3_disorder"
"youtu.be"          = "fake_split_goodsum_ttl3_disorder"
"discord.com"       = "fake_split_goodsum_ttl3_disorder"
"discordapp.com"    = "fake_split_goodsum_ttl3_disorder"
"discordapp.net"    = "fake_split_goodsum_ttl3_disorder"
"discordcdn.com"    = "fake_split_goodsum_ttl3_disorder"
"discord.media"     = "fake_split_goodsum_ttl3_disorder"
"discord.gg"        = "fake_split_goodsum_ttl3_disorder"
```

Правила:

* ключ сравнивается по суффиксу, самое длинное совпадение побеждает
  (`api-v2.soundcloud.com` → `soundcloud.com`);
* остальные домены продолжают идти через глобальную `strategy`;
* QUIC/UDP-настройки переопределение не затрагивает.

Из CLI:

```bash
# добавить/заменить переопределение и перезапустить
sudo nadejda set-config --override soundcloud.com=fake_split_goodsum_ttl3_disorder --restart
# несколько сразу
sudo nadejda set-config --override a.com=split_sni --override b.com=frag
# убрать все переопределения
sudo nadejda set-config --clear-overrides --restart
```

Текущие переопределения видны в `nadejda status` (строка `overrides:`).

### Стратегии

| Имя | Суть |
|---|---|
| `multisplit` | несколько разрезов ClientHello (по умолчанию: быстро и надёжно) |
| `seqovl568` | перекрытие sequence number с декоем |
| `seqovl_sni` | то же, разрез в середине SNI |
| `seqovl300` | меньшее перекрытие |
| `multisplit` | несколько разрезов ClientHello |
| `split1` / `split_sni` | простой разрез |
| `disorder` | сегменты в обратном порядке |
| `fake_split` / `fake_split6` | поддельный ClientHello с малым TTL + разрез |
| `fake_split_goodsum_ttl3` | подделка с правильной контрольной суммой и TTL 3 |
| `fake_split_goodsum_ttl3_disorder` | то же + сегменты в обратном порядке (часто самый стабильный) |
| `fake_seqovl` | подделка + перекрытие |
| `frag` / `frag_split` | фрагментация IP |
| `split1_disorder` | несколько разрезов + обратный порядок |

Выбрать вручную: `strategy = "fake_split6"` в конфиге. Перебрать все:
`sudo nadejda autotune --save`.

UDP/QUIC-стратегии (`[udp] strategy`):

| Имя | Суть |
|---|---|
| `quic_frag` | резать QUIC Initial на IP-фрагменты, хвост первым (рекомендуется) |
| `quic_frag_early` | первый фрагмент короче (32 байта нагрузки), агрессивнее |
| `quic_frag_mid` | первый фрагмент длиннее (128 байт) |
| `quic_frag_inorder` | фрагменты по порядку (для сетей, не любящих reordering) |
| `zapret_quic` | fake: поддельный QUIC Initial от `www.google.com` x6, исходный TTL |
| `zapret_game` | агрессивный fake для игрового фильтра; голос всё равно `discord_udp` |
| `quic_off` | не вмешиваться в UDP/443 |

TCP- и UDP-стратегии работают одновременно: выбор TCP-стратегии не отключает
QUIC-обход и наоборот.

Дополнительные домены и исключения:

```toml
[hosts]
extra_domains = ["example.org", "cdn.example.net"]
extra_file = "/etc/nadejda/extra-hosts.txt"
# Никогда не трогать эти домены и их поддомены.
exclude = ["sberbank.ru", "gosuslugi.ru", "steampowered.com"]
```

`exclude` действует и на TCP-десинхронизацию: ClientHello с таким SNI
проходит без изменений. Это удобно для банков, госуслуг и лаунчеров,
которые ломаются от подмены.

Встроенные списки для GitHub, YouTube, Spotify, SoundCloud, ChatGPT и Discord
уже включены (см. `nadejda/config.py`).

---

## Диагностика

**Сайт всё ещё не открывается.** Проверьте по шагам:

```bash
sudo nadejda doctor
nadejda test github.com www.youtube.com
nadejda logs -n 100
```

* `DNS-over-TLS failed` — порт 853 закрыт. Попробуйте другие серверы в
  `dns_upstreams` или `dns_fallback_udp = true`.
* `403` после успешного TLS — это ответ сервера, а не DPI (см. ниже).
* TLS-таймаут на конкретном домене, остальные работают — попробуйте другую
  стратегию (`autotune` или вручную `fake_split6`, `frag_split`).
* Сайт открывается, но тело ответа приходит по 5–10 КБ и загрузка висит —
  это **троттлинг по SNI**: провайдер пропускает рукопожатие, а потом режет
  поток. `nadejda test` теперь показывает, сколько килобайт успело прийти, а
  `autotune` проверяет именно скачивание данных, а не только TLS. Запустите
  `sudo nadejda autotune --quick --save` (или «Автоподбор» в GUI) — он
  переберёт варианты `fake_split` с разным TTL, контрольной суммой и
  `disorder`/`seqovl` и выберет тот, который реально качает страницы.
* Приложение висит на «Starting…» или на логотипе загрузки, а в `ss -tin` у
  соединения видно `bytes_acked=1` (сервер не подтвердил даже ClientHello)
  либо `unacked`/`backoff` растут, а `lastrcv` — минуты. Это значит, что
  провайдер «зачернил» весь поток. Nadejda замечает, что клиент снова и снова
  отправляет одни и те же байты, и через ~1.5 с сбрасывает соединение — клиент
  сразу открывает новое и получает новый шанс пройти DPI. В журнале это строка
  `stall reset ...`. Отключается через `stall_reset = false` в `[general]`.
  Сброс не помогает, если провайдер режет только ответ сервера (клиенту нечего
  переотправлять): тогда помогает перезагрузка страницы/приложения — новый
  поток с новым вердиктом DPI.
* Совсем ничего не работает — проверьте, не запущены ли zapret/byedpi
  (`nadejda doctor` это показывает), и не блокирует ли трафик локальный фаервол.

**После запуска остался «старый» DNS-ответ.** Очистите кэши:

```bash
sudo resolvectl flush-caches 2>/dev/null
# в браузере: chrome://net-internals/#dns → Clear host cache
```

**Браузер использует свой DNS (DoH).** Это нормально: DoH идёт мимо
перехвата и обычно сам по себе устойчив к подмене. Если наоборот мешает —
отключите «Secure DNS» в настройках браузера.

**YouTube тормозит, но открывается.** Видео идёт с `googlevideo.com`.
Оставьте `quic = "desync"`, но проверьте, что YouTube есть в
`[udp] force_tcp_domains`: его QUIC часто режут глубже, чем помогает
фрагментация, и тогда нужен быстрый откат на TCP. Если YouTube наоборот
открывается только по QUIC — уберите домены из `force_tcp_domains` и
попробуйте `[udp] strategy = "quic_frag_early"`. Для TCP попробуйте
`seqovl_sni` или `fake_split6`.

**В Discord не грузятся некоторые демонстрации экрана.** Звонок и звук идут
по UDP на медиасерверы Discord (порты 19305–19331 и ~50000), а часть
WebRTC-путей — через TURN Cloudflare на UDP/443. Nadejda трогает только
QUIC Initial на UDP/443; TURN/RTP-датаграммы и медиапорты Discord проходят
без изменений.

Если при этом сам клиент Discord долго грузит страницы и вложения, это тот же
троттлинг TCP после рукопожатия, что у SoundCloud и YouTube: браузерный
ClientHello даёт `200` и ~2.7 КБ за 8 с. Поэтому домены Discord добавлены в
`[overrides]` с fake-стратегией (`discord.com`, `discordapp.com`,
`discordapp.net`, `discordcdn.com`, `discord.media`, `discord.gg`). На голос и
демонстрацию экрана это не влияет — они по-прежнему идут через UDP.

В режиме `quic = "block"` адреса Cloudflare
(`104.28.0.0/14`, `162.158.0.0/15`, `172.64.0.0/13` и др.) дополнительно
исключены, чтобы RTC не получал ICMP недоступен. Проверить, что правило не
рубит медиасервер:

```bash
sudo nft list chain inet nadejda out      # счётчики allow/reject
```

Если счётчик `reject` растёт, а демонстрации всё равно не грузятся, посмотрите
лог Discord (`~/.config/discord/logs/renderer_js.log`): строки
`OnConnectAttemptTimedOut` и `NO_ROUTE` означают, что провайдер режет UDP до
медиасервера, а не SNI. Часть потоков Discord выдаёт на релеи Google Cloud
(например, `35.217.x.x`, UDP-порт около `50000`), которые провайдер может
дропать целиком — Nadejda обрабатывает только TCP/443, UDP/443 и DNS/53, так
что на такой поток она повлиять не может. В этом случае поможет только
VPN/прокси (например, WARP в split-tunnel для Discord) или смена голосового
региона сервера; DPI-обход по SNI на UDP не влияет.

**SoundCloud открывается, но музыка не играет.** У SoundCloud две разные
проблемы, и их надо проверять по отдельности.

1. DNS-подмена. Провайдер может отдавать для `soundcloud.com` приватный
   адрес (`10.x.x.x`) вместо настоящего CloudFront. Проверьте:

   ```bash
   getent ahostsv4 soundcloud.com        # системный (возможно, подменённый) DNS
   nadejda status                        # dns proxy должен быть on
   ```

   Если адрес приватный, а `dns = true` — значит браузер/приложение ещё
   держит старый ответ: очистите кэш DNS (см. ниже) и перезапустите браузер.
   DoT-резолвер Nadejda отдаёт настоящие адреса CloudFront.

2. Сброс по SNI. `soundcloud.com` и его поддомены провайдер рвёт прямо во
   время рукопожатия (`write:errno=104` / `Connection reset by peer`), причём
   `multisplit` от этого не защищает: он прячет SNI только от DPI без
   реассемблинга. Поэтому для домена нужна fake/seqovl-стратегия:

   ```toml
   [desync]
   strategy = "multisplit"

   [overrides]
   "soundcloud.com"   = "fake_split_goodsum_ttl3_disorder"
   "soundcloud.cloud" = "fake_split_goodsum_ttl3_disorder"
   "sndcdn.com"       = "fake_split_goodsum_ttl3_disorder"
   ```

   Если и это не помогает, попробуйте в `[overrides]` значения `fake_seqovl`,
   `seqovl568` или `split1_disorder`. Проверить домен отдельно:

   ```bash
   nadejda test soundcloud.com api-v2.soundcloud.com a-v2.sndcdn.com
   ```

   Обратите внимание: медиа идёт с `*.sndcdn.com` и `*.soundcloud.cloud`, а
   метаданные — с `api-v2.soundcloud.com`. Если страница открывается, а трек
   не играет, проблема почти всегда в CDN-хостах, а не в самом `soundcloud.com`.

3. Троттлинг медиа после рукопожатия. Самая частая причина «страница есть, а
   музыки нет»: плейлист и сегменты отдаёт
   `playback.media-streaming.soundcloud.cloud`, TLS и заголовки проходят, а
   тело режется до ~0.5 КБ/с (плейлист 19 КБ не дочитывается за 10–15 с).
   Имя хоста при этом попадает в DPI, поэтому помогает тот же fake-приём, что
   и для `soundcloud.com`, — отсюда `"soundcloud.cloud"` в `[overrides]`.
   Проверить, что дело именно в этом, можно так:

   ```bash
   curl -o /dev/null -w 'code=%{http_code} size=%{size_download} speed=%{speed_download}\n' \
     "$(yt-dlp -f bestaudio --get-url 'https://soundcloud.com/forss/flickermood' | tail -1)"
   ```

   До override: `size=3958 speed≈400`; после: `size=19443 speed≈36000` и трек
   целиком скачивается за десятки секунд.

4. CloudFront может временно резать ваш IP после серии тестов (сотни запросов
   подряд): соединения сбрасываются за 0.1 с и без Nadejda. Подождите пару
   минут и проверьте снова, прежде чем менять стратегию.

**Не запускается после обновления ядра/пакета.** `nft` мог измениться —
`sudo nadejda doctor`, затем `sudo nadejda start -f` и посмотрите ошибку.

---

## Важное ограничение: ChatGPT

На проверенной сети `chatgpt.com` отвечает **HTTP 403 от Cloudflare** уже
после успешного TLS-рукопожатия, причём с настоящих IP-адресов. Это
**серверное гео-ограничение**, а не DPI: Nadejda меняет форму TCP-пакетов,
но не страну источника. Обход DPI здесь принципиально не поможет — нужен
VPN/прокси с выходом в разрешённой стране. `nadejda test` выводит об этом
отдельное примечание.

То же относится к любым блокировкам по IP и к сервисам, которые целиком
заблокированы на уровне маршрутизации.

---

## Тесты

Тесты поднимают изолированный network namespace (не трогают реальную сеть)
и проверяют NFQUEUE, переинъекцию, байтовый поток на сервере и перехват DNS:

```bash
make test
# или по отдельности:
python3 tests/config_test.py          # правка конфига без потери комментариев
python3 tests/guard_test.py           # сброс «мёртвых» потоков и стартовая очистка
python3 tests/zapret_test.py          # профили zapret, fake-UDP, голос, firewall
unshare -Urn python3 tests/netns_nfq_smoke.py
unshare -Urn python3 tests/netns_engine_test.py
unshare -Urn python3 tests/netns_dns_test.py
```

Сетевые тесты требуют `unshare` из `util-linux` и работающего user-namespace;
остальные работают всегда. Тестам root не нужен.

`tests/zapret_test.py` проверяет без root: параметры профилей `zapret_*`,
циклическое заполнение перекрытия блобами, `ip-id=0`, fake-TCP с TTL 3 и
битой суммой, fake-QUIC с валидной суммой и исходным TTL, голосовые порты,
неизменность STUN на UDP/443,
правила nftables (порты, cutoff, Game Filter) и решения движка
(исключения, overrides, cutoff, голос при `quic = "off"`).

---

## Удаление

```bash
sudo ./install.sh --uninstall
```

Удаляются `/opt/nadejda`, `/usr/local/bin/nadejda`, `/usr/local/bin/nadejda-gui`,
ярлык и иконка из меню, systemd-юнит, правила nftables, pid-файл и лог.
Конфигурация в `/etc/nadejda` сохраняется — удалите вручную, если она больше
не нужна.

---

## Структура проекта

```
nadejda/
  nfqueue.py    клиент NFQUEUE на чистом netlink (без libnetfilter_queue)
  packet.py     разбор/сборка IP и TCP, контрольные суммы, парсер SNI
  desync.py     стратегии и построение плана пакетов
  payloads.py   встроенные блобы zapret (ClientHello, QUIC, Discord UDP)
  engine.py     оркестрация: nftables, очередь, sender, DNS, статистика
  firewall.py   правила nftables и адресные наборы
  resolver.py   DNS-over-TLS / UDP
  dnsserver.py  локальный DNS-прокси
  hostlist.py   сопоставление SNI со списком доменов
  config.py     конфиг, встроенные списки, TOML
  cli.py        команды nadejda
  gui.py        графический интерфейс GTK4 / libadwaita
config/config.toml    конфиг по умолчанию
data/nadejda.svg      иконка приложения
data/io.github.nadejda.Nadejda.desktop  ярлык для меню
systemd/nadejda.service
install.sh
tests/                тест конфига + интеграционные тесты в network namespace
```

---

## Дисклеймер

Инструмент предназначен для защиты приватности и восстановления доступа к
собственным сервисам в сетях с необоснованной фильтрацией. Используйте его в
соответствии с законодательством вашей страны и правилами провайдера.
Автор не несёт ответственности за последствия применения.
