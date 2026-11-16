Nadejda 1.1.1 для Windows (x64)
================================

Что это
-------
Nadejda обходит DPI-блокировки, перестраивая исходящие пакеты локально:
разрезает TLS ClientHello, подмешивает fake-пакеты с низким TTL и
перекрывает последовательность (seqovl). Трафик не идёт через чужие
серверы, TLS не расшифровывается.

В архиве два файла:
  Nadejda.exe      графический интерфейс
  nadejda-win.exe  командная строка (test, doctor, status, start, stop)

Требования: Windows 10/11 x64, права администратора.
Python не нужен.

Запуск
------
1. Распакуйте архив в любую папку (например, C:\Nadejda).
2. Запустите Nadejda.exe. Windows покажет запрос UAC — разрешите.
3. Нажмите Test, затем Start.

При первом запуске создаётся конфиг:
  C:\ProgramData\Nadejda\config.toml
Лог:
  C:\ProgramData\Nadejda\nadejda.log

Командная строка (cmd или PowerShell от администратора):
  nadejda-win.exe test
  nadejda-win.exe doctor
  nadejda-win.exe status
  nadejda-win.exe start
  nadejda-win.exe stop

Если Windows SmartScreen пишет «Windows защитила ваш компьютер»
---------------------------------------------------------------
Файлы не подписаны сертификатом разработчика, поэтому SmartScreen
предупреждает. Нажмите «Подробнее» -> «Выполнить в любом случае».
Антивирус может ругаться на драйвер WinDivert — он подписан и используется
многими легальными программами (zapret, GoodbyeDPI). При необходимости
добавьте папку с Nadejda в исключения.

Автозапуск при входе (без UAC)
------------------------------
Создайте задачу планировщика с правами администратора (путь замените на
свой):

  schtasks /Create /TN Nadejda /TR "C:\Nadejda\Nadejda.exe" /SC ONLOGON /RL HIGHEST /F

Удалить задачу:

  schtasks /Delete /TN Nadejda /F

Настройка
---------
Формат config.toml такой же, как в Linux-версии: [general], [desync],
[udp], [overrides]. После правки перезапустите движок (Stop -> Start).
Автоподбора стратегии на Windows нет — перебирайте пресеты в списке TCP.

Если не работает
----------------
1. nadejda-win.exe doctor — проверить pydivert, права и фильтр.
2. nadejda-win.exe test — проверить выбранную стратегию.
3. Посмотрите C:\ProgramData\Nadejda\nadejda.log.
4. «Access is denied» — запустите от имени администратора.

Удаление
--------
Остановите движок, удалите папку с exe. При желании удалите
C:\ProgramData\Nadejda (конфиг и лог).

Лицензия: MIT.
