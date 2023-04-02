
HowTo. l2fwd.
-------------

1. Доработки в файлах:

    filter_rules.c
    filter_rules.h
    filter_srv.c

    Отключить доработки можно комментирование макроса в файле filter_rules.h
    и пересборкой программы:

    // comments this define it will completely turns off FILTER feature
    // #define USE_PACKET_FILTER

2. Доработки применяются в файле main.c и "прикрыты" макросом 
    #ifdef USE_PACKET_FILTER
    #endif

2.1 Запуск сервера приема правил фильтрации в "открепленном" потоке.
    Механизма остановки сервера нет - убивается вмесе с окончанием работы программы.

2.2 Установка callback-ов для RX-пакетов

2.3 Отключение cfllback-ов


