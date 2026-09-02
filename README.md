# Mozilla PKI URL Collector

## 1. Назначение проекта

Проект предназначен для формирования актуального перечня URL инфраструктуры публичных удостоверяющих центров, сертификаты которых доверены Mozilla.

Собираются три основных типа URL:

- **CRL** — Certificate Revocation List;
- **OCSP** — Online Certificate Status Protocol;
- **CA Issuers** — URL сертификата издателя, указанный через Authority Information Access (AIA).

Полученные списки могут использоваться, например, для подготовки правил исходящего сетевого доступа в корпоративной инфраструктуре.

Проект **не генерирует правила firewall**. Он предоставляет исходные данные в удобном для дальнейшей обработки виде.

---

## 2. Источники данных

Проект использует публичные ресурсы Mozilla/CCADB:

1. **CCADB AllCertificateRecords REST API**

   Используется для получения записей сертификатов и связанных с ними данных.

2. **CCADB All Certificate PEMs Year**

   Используется для получения самих сертификатов в PEM-формате по году `NotBefore`.

После получения сертификатов выполняется непосредственный разбор X.509 extensions.

---

## 3. Какие сертификаты обрабатываются

Из CCADB выбираются сертификаты, относящиеся к Mozilla CA Certificate Program.

Для Root CA используется условие:

```text
Mozilla Status = Included
```

Для Intermediate CA:

```text
Mozilla Status = Trusted
```

Дополнительно исключаются сертификаты, которые ещё не вступили в силу или срок действия которых уже закончился.

Таким образом, результат ориентирован на текущий набор сертификатов, используемых Mozilla для доверия.

---

## 4. Получение записей CCADB

Используется публичный endpoint:

```text
https://ccadb.my.site.com/services/apexrest/v1/allcertificaterecords
```

Запрос выполняется методом `POST`.

Используется field set:

```json
{
  "fieldSets": [
    "PertainingToCertificatesIssued"
  ]
}
```

Для ограничения объёма данных используется фильтр:

```json
{
  "filters": {
    "notBeforeDecade": 2020,
    "PageNumber": 1
  }
}
```

Год/десятилетие выбирается автоматически исходя из текущей даты.

CCADB API возвращает результаты постранично. Скрипт автоматически обрабатывает все страницы через `NextPageNumber`.

---

## 5. Получение CRL URL

CRL URL извлекаются двумя способами.

### 5.1. Из CCADB API

Из поля `PertainingToCertificatesIssued` используются:

```text
JSONArrayOfAllFullCRLURLs
JSONArrayOfPartitionedCRLs
```

Это позволяет получить:

- полные CRL;
- partitioned CRL.

### 5.2. Из X.509 сертификата

Для каждого выбранного сертификата дополнительно разбирается extension:

```text
CRL Distribution Points
```

Из него извлекаются URI:

```text
http://...
https://...
```

Оба источника объединяются и дедуплицируются.

---

## 6. Получение OCSP URL

OCSP URL извлекается непосредственно из X.509 extension:

```text
Authority Information Access (AIA)
```

Обрабатывается access method:

```text
id-ad-ocsp
```

Результат записывается как:

```text
OCSP
```

Например:

```text
http://ocsp.example.com/
```

---

## 7. Получение CA Issuers URL

CA Issuers также извлекается из:

```text
Authority Information Access (AIA)
```

Обрабатывается access method:

```text
id-ad-caIssuers
```

Результат записывается как:

```text
CA_ISSUERS
```

Например:

```text
http://ca.example.com/issuer.crt
```

---

## 8. Почему используются именно X.509 extensions

Для OCSP и CA Issuers наиболее надёжным источником является непосредственно сертификат.

Это позволяет избежать зависимости от названий или структуры отдельных полей CCADB.

Фактическая структура сертификата выглядит концептуально так:

```text
Certificate
├── CRL Distribution Points
│   └── CRL URL
│
└── Authority Information Access
    ├── OCSP
    │   └── OCSP URL
    │
    └── CA Issuers
        └── CA Issuers URL
```

---

## 9. Кэширование

Загруженные PEM CSV сохраняются локально в:

```text
mozilla-pki-urls/cache/
```

Например:

```text
cache/
├── AllCertificatePEMs_2024.csv
├── AllCertificatePEMs_2025.csv
└── AllCertificatePEMs_2026.csv
```

Если файл уже существует и имеет ненулевой размер, повторная загрузка не выполняется.

Это позволяет:

- продолжить выполнение после прерывания;
- не скачивать повторно большие файлы;
- уменьшить нагрузку на CCADB.

---

## 10. Результаты

После выполнения создаётся каталог:

```text
mozilla-pki-urls/
```

### `mozilla_pki_urls.csv`

Основной подробный результат.

Поля:

```text
type
url
hostname
certificate_sha256
certificate_name
record_type
mozilla_status
source
```

Пример:

```text
CRL,http://crl.example.com/root.crl,crl.example.com,...
OCSP,http://ocsp.example.com/,ocsp.example.com,...
CA_ISSUERS,http://ca.example.com/issuer.crt,ca.example.com,...
```

Поле `source` позволяет определить происхождение URL:

```text
CCADB API
X.509 CRL Distribution Points
X.509 AIA / OCSP
X.509 AIA / CA Issuers
```

---

### `crl_urls.txt`

Уникальный список CRL URL:

```text
http://crl.example.com/root.crl
http://crl.example.com/intermediate.crl
...
```

---

### `ocsp_urls.txt`

Уникальный список OCSP URL:

```text
http://ocsp.example.com/
http://ocsp2.example.net/
...
```

---

### `ca_issuers_urls.txt`

Уникальный список CA Issuers URL:

```text
http://ca.example.com/root.crt
http://ca.example.net/intermediate.crt
...
```

---

### `mozilla_ca_certificates.csv`

Инвентаризация обработанных сертификатов.

Содержит:

```text
ccadb_id
certificate_name
record_type
mozilla_status
valid_from
valid_to
sha256
parent_sha256
```

Этот файл позволяет установить связь между сертификатом и URL, найденными в его extensions.

---

### `summary.txt`

Краткая статистика выполнения:

```text
Generated UTC: ...
Selected CCADB records: ...
Unique certificates: ...
Unique CRL URLs: ...
Unique OCSP URLs: ...
Unique CA Issuers URLs: ...
Unique total URLs: ...
```

---

## 11. Установка

Требуется Python 3.10+.

Установка зависимостей:

```bash
python3 -m pip install requests cryptography
```

---

## 12. Запуск

```bash
python3 mozilla_pki_urls.py
```

Скрипт не требует:

- учётной записи CCADB;
- Salesforce login;
- API token;
- Mozilla account.

---

## 13. Принцип работы

Общая схема:

```text
                   ┌─────────────────────┐
                   │       CCADB API     │
                   │ AllCertificateRecords│
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Фильтрация Mozilla  │
                   │ Included / Trusted   │
                   │ + validity           │
                   └──────────┬──────────┘
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
        ┌─────────────────┐       ┌──────────────────┐
        │ CRL из CCADB    │       │ SHA-256 certs    │
        │ Full/Partitioned│       └────────┬─────────┘
        └────────┬────────┘                │
                 │                         ▼
                 │                ┌──────────────────┐
                 │                │ CCADB PEM CSV    │
                 │                │ по годам         │
                 │                └────────┬─────────┘
                 │                         │
                 │                         ▼
                 │                ┌──────────────────┐
                 │                │ X.509 parser     │
                 │                ├──────────────────┤
                 │                │ CRL Distribution │
                 │                │ AIA / OCSP       │
                 │                │ AIA / CA Issuers │
                 │                └────────┬─────────┘
                 │                         │
                 └────────────┬────────────┘
                              ▼
                   ┌─────────────────────┐
                   │ Deduplication        │
                   └──────────┬──────────┘
                              ▼
                   ┌─────────────────────┐
                   │ CSV + TXT списки    │
                   └─────────────────────┘
```

---

## 14. Важные особенности

### HTTP URL не удаляются

Многие CRL и OCSP endpoints публикуются через HTTP:

```text
http://...
```

Это нормально для PKI.

Поэтому проект сохраняет как:

```text
http://
https://
```

и не пытается автоматически заменить HTTP на HTTPS.

### IP-адреса не фиксируются

Результат содержит URL и hostname, но не строит постоянный список IP-адресов.

Это важно, поскольку инфраструктура CA может использовать:

- CDN;
- load balancer;
- DNS balancing;
- меняющиеся IP-адреса.

Если результат используется для сетевой фильтрации, предпочтительно использовать FQDN-based policy, если это поддерживает используемый firewall.

---

## 15. Дедупликация

Один и тот же URL может встречаться:

- у нескольких сертификатов;
- одновременно в CCADB и X.509;
- у нескольких intermediate CA.

Поэтому итоговые TXT-файлы содержат только уникальные URL.

В CSV сохраняется первая найденная связь URL с сертификатом и источник обнаружения.

---

## 16. Ограничения

Проект формирует список инфраструктуры, связанной с сертификатами Mozilla CA Program.

Он не утверждает, что полученный список является универсальным списком **всех** URL, которые когда-либо могут понадобиться TLS-клиенту.

Например, конкретный сервер может использовать:

- частный корпоративный CA;
- дополнительный trust store;
- сертификат, отсутствующий в Mozilla Root Store;
- специфическую инфраструктуру проверки отзыва.

Такие адреса проект намеренно не добавляет.

---

## 17. Рекомендуемое регулярное обновление

Список следует периодически обновлять, поскольку:

- появляются новые CA;
- меняются intermediate certificates;
- изменяются CRL/OCSP endpoints;
- сертификаты истекают;
- Mozilla может изменять доверительный статус CA.

Практический вариант — запускать сборщик, например, **раз в сутки или раз в неделю**, а результат использовать как входные данные для внутреннего процесса актуализации сетевых правил.

При частом запуске PEM-файлы будут использоваться из локального cache, если они уже были скачаны.

---

## 18. Безопасность

Скрипт не передаёт в CCADB никаких пользовательских данных или учётных данных.

Все запросы выполняются к публичным ресурсам.

Полученные сертификаты используются только для локального разбора публичных X.509 extensions.

---

## 19. Файлы проекта

```text
mozilla_pki_urls.py
```

Основной Python-скрипт.

```text
mozilla-pki-urls/
```

Рабочий каталог с результатами.

```text
mozilla-pki-urls/cache/
```

Локальный кэш исходных PEM CSV.

---

## 20. Лицензирование и назначение

Скрипт является инструментом автоматизации сбора публичной PKI-информации.

Он не изменяет данные CCADB и не выполняет операции от имени пользователя.

При использовании результатов в корпоративном firewall следует учитывать собственную PKI, политики безопасности и требования конкретных приложений.
