# vpnctl v2 — handoff для продолжения продуктовой сессии

> [!IMPORTANT]
> Раздел «Актуальный snapshot решений» является источником истины для
> продолжения discovery. Если более старые разделы ниже называют принятое
> решение гипотезой или открытым вопросом, приоритет имеет snapshot.

## Актуальный snapshot решений

Последнее обновление: **2026-09-03**.

Стадия: discovery завершён и формализован в OpenSpec change
`openspec/changes/vpnctl-v2`; реализация идёт в ветке `feat/vpnctl-v2`.
Proposal, десять capability specs, technical design и полный task graph готовы
и проходят strict validation. После завершения task 7.9 выполнено `63/156`
задач: готовы baseline/contracts, blocking spikes, model/store/secrets,
CLI/output/consent, host init, control plane и personal-client foundation до
детерминированного WireGuard и Clash/Mihomo rendering включительно. Следующая
задача — 7.10 (атомарная файловая публикация exports, permissions, overwrite,
scp hints и generation metadata). Фактический Clash Mi остаётся release-gate
16.11, а restricted alternative в Clash export — задача 8.10.

### 1. Product contract

- `vpnctl v2` — opinionated gateway orchestrator, а не универсальный конструктор
  сетевых компонентов и не только WireGuard manager.
- Основной пользователь — один разработчик/self-hoster, арендующий VPS во
  внешнем регионе и, при необходимости, VPS в ограниченном регионе.
- Gateway — выделенная машина только для vpnctl. Пользовательские приложения на
  gateway не размещаются.
- Gateway является универсальным edge-узлом владельца: через него может идти
  трафик личных устройств и выбранный серверный трафик private VPS.
- Gateway предоставляет только выход в другой сегмент интернета и ingress к
  явно опубликованным приложениям. Доступ к приватным сетям и node-to-node
  connectivity не входят в v2.
- Поддерживаются несколько private nodes и несколько client devices. Nodes и
  clients изолированы друг от друга.
- Первый поддерживаемый environment: Ubuntu 24.04 LTS, Linux amd64, systemd,
  native services, запуск системных операций от root. Docker не используется.
- Host обязан предоставлять `/dev/net/tun`, kernel WireGuard, nftables, policy
  routing/conntrack marks, systemd/systemd-resolved и возможность включить IPv4
  forwarding на gateway. Эти capabilities проверяются preflight до mutation.
- `wireguard-go`, альтернативные firewall backends и restricted
  OpenVZ/LXC-like environments без необходимых kernel capabilities в v2.0 не
  поддерживаются; отсутствие capability является actionable init error.

### 2. Канонические сценарии

#### Personal VPN

Пользователь арендует одну VPS во внешнем регионе, устанавливает vpnctl в
минимум команд и получает клиентский конфиг для личного устройства. Первый
целевой клиент — Clash Mi на iOS; сохраняется WireGuard-compatible flow v1.

```text
iOS / macOS / Steam Deck → Gateway → Internet
```

Минимальный happy path для нового Clash Mi client после однократного gateway
init/SSH confirmation:

```bash
sudo vpnctl client add iphone telegram openai anthropic
sudo vpnctl client export iphone clash
```

Initial presets указаны явно; export не объединяется с identity creation и не
печатает secret-bearing profile в stdout. Result показывает managed path и
готовую `scp` command. Для full-tunnel WireGuard presets не требуются:

```bash
sudo vpnctl client add steamdeck
sudo vpnctl client export steamdeck wireguard
```

#### Gateway + private node

Пользователь арендует gateway VPS во внешнем регионе и private VPS в
ограниченном регионе. vpnctl связывает их и предоставляет:

```text
selected egress: Private node → Gateway → Internet
default egress:  Private node → Internet directly
managed ingress: Internet → Gateway:443 → Private node application
```

Первый ingress use case — Telegram webhook и обычные HTTP API requests.

### 3. Installation, роли и публичный CLI

- Публичная CLI grammar v2.0 заморожена в `docs/v2/CLI_CONTRACT.md`. Этот
  machine-checked registry является authoritative для command names, role
  availability, arguments, consent, `--dry-run`/`--defer` и examples; более
  ранние иллюстрации в snapshot читаются через этот контракт.
- Верхний уровень CLI использует hybrid model: частые workflows являются
  короткими top-level commands (`init`, `invite`, `join`, `expose`, `status`,
  `doctor`, `plan`, `apply`, `repair`, `backup`, `restore`, `update`,
  `uninstall`, `purge`), а управление коллекциями сгруппировано по nouns
  (`node`, `client`, `preset`, `policy`, `transport`).
- После init роль host известна и не повторяется в каждой команде. Команда на
  private node по умолчанию относится к этому node; операции над другими nodes
  выполняются локально на gateway через group `node`. Unsupported command for
  current role завершается понятной validation error до изменений.
- Поставляется один бинарник `vpnctl`. Разделение на внутренние процессы или
  role-specific implementation не является частью публичного API.
- Installer универсален и только устанавливает бинарник. Назначение машины
  выбирается при инициализации:

```bash
sudo vpnctl init --gateway --public-ip 203.0.113.10
sudo vpnctl init --node
```

- `--gateway` и `--node` взаимоисключающие; один из них обязателен.
- Gateway init имеет только четыре optional advanced overrides:
  `--client-cidr`, `--node-cidr`, `--external-interface`, `--ssh-port`.
  Default pools — `10.66.0.0/24` и `10.67.0.0/24`; interface и SSH port
  определяются локально и показываются в plan.
- Public listeners `443/TCP`, `8443/TCP` и `51820/UDP` в v2.0 фиксированы и не
  имеют init flags. DNS меняется через `vpnctl dns`, initial node transport
  выбирается в `join`, advanced init config file отсутствует.
- Повторный `init` с той же ролью идемпотентен. Смена роли обычным повторным
  `init` запрещена и требует явного reinitialize/migration flow.
- Public IPv4 gateway является обязательным явным input. vpnctl не определяет
  его через внешний сервис.
- `init` устанавливает и запускает только компоненты выбранной роли. Наличие
  кода другой роли в одном бинарнике не означает запуск лишних сервисов.
- CLI по умолчанию выдаёт короткий human-readable result. Все operational и
  mutating commands поддерживают единый global `--json` mode для automation.
- JSON stdout содержит ровно один document со стабильными в пределах major
  version полями: как минимум `schema_version`, result/resource identifiers,
  status, `warnings` и `requires_action`. Progress и техническая диагностика
  направляются в stderr.
- Secret-bearing значения и sensitive webhook paths не включаются в JSON.
  Команды, которые по своему назначению должны однократно показать secret
  человеку, используют отдельный явный interactive output flow.
- Exit codes имеют стабильные категории как минимум для success, validation
  error, conflict, unavailable/degraded и internal error; точные numeric values
  будут определены вместе с финальной CLI grammar.
- Confirmation policy зависит от impact. Обычные обратимые operations
  (`invite`, `client add`, `policy set/clear`, `expose` creation, `dns set/reset`,
  `transport test`) применяются без prompt после validation.
- Confirmation обязателен для `init`, `join`, node/client
  revoke/delete/rotate, `expose remove`, `transport switch`, `cert rotate`,
  `repair`, restore, update/rollback, uninstall/purge, а также `apply`, если его
  plan содержит destructive или availability-impacting changes.
- Global `--yes` пропускает обычный yes/no prompt, но не вводит invite token или
  backup passphrase и не обходит typed confirmation для purge,
  `--include-backups` или irreversible migration. `--json` не означает consent.
  Non-interactive command с обязательным prompt завершается до mutation, если
  разрешённый `--yes` не передан. `--dry-run` prompt не показывает.
- Lockout-risk network transaction подтверждается из новой SSH-сессии короткой
  локальной командой `vpnctl confirm <transaction-id>`. `confirm` принимает
  одноразовый short ID, не показывает дополнительный prompt и не является
  универсальным consent mechanism для других destructive operations. Если
  120-second watchdog уже выполнил rollback, команда сообщает expired/rolled
  back result и ничего не меняет.
- Public ingress certificate имеет gateway-only grammar:

```text
vpnctl cert show
vpnctl cert export [output-path]
vpnctl cert rotate
```

- `cert show` выводит public IP, fingerprint, validity и expiration warning.
  Export копирует только public certificate; default target —
  `/var/lib/vpnctl/exports/gateway.crt`.
- `cert rotate` показывает affected exposes, требует подтверждения, применяется
  только immediately и не поддерживает `--defer`. Все exposes получают
  `requires_action` повторно зарегистрировать external webhook с новым cert.
  Старый private key сохраняется только в ограниченном rollback snapshot.
- `expose show` на private node может получить через gateway актуальную public
  certificate copy для последующего `scp`.
- Gateway-side node management grammar:

```text
vpnctl node list
vpnctl node show <name-or-id>
vpnctl node revoke <name-or-id>
vpnctl node delete <name-or-id>
vpnctl node recover <name-or-id>  # gateway: issue recovery invite
vpnctl node recover               # private node: hidden token prompt
```

- `list/show` не выводят secrets. Node name уникален среди существующих records,
  immutable ID остаётся канонической identity.
- `node revoke` является немедленной gateway-only security operation,
  показывает affected exposes, требует подтверждения и не поддерживает
  `--defer`. `node delete` разрешён только после revoke и также требует
  подтверждения.
- Credential rotation запускается только на самом private node как
  `vpnctl node rotate`. Одна transaction ротирует весь node-scoped credential
  set: control identity key, WireGuard key, Shadowsocks/ShadowTLS credentials и
  reverse-tunnel token. Gateway ingress certificate и immutable node ID в эту
  операцию не входят.
- Новые private keys и symmetric secrets создаются локально на private node и
  передаются gateway только по старому authenticated control channel в
  необходимой форме. Gateway не инициирует rotation удалённо, потому что
  постоянного node agent нет.
- Rotation использует согласованный parallel rollout без downtime: gateway
  временно принимает old и new credential generations, node поднимает и
  проверяет новые control/standard/restricted/tunnel connections, traffic
  переключается, старые connections дренируются, после чего old generation
  отзывается. Временно могут существовать два tunnel/transport generations,
  но steady state остаётся single-active.
- Операция атомарна на уровне credential set: partial commit запрещён. Ошибка до
  финального commit оставляет всё старое поколение рабочим; node name, overlay
  IP, policies и exposes не меняются. Для локального просмотра используется
  общий `vpnctl status`, а не отдельный `node status`.
- `node recover` является role-aware break-glass grammar. На gateway обязательный
  target выбирает существующий node и после confirmation создаёт recovery
  invite; на private node target запрещён, потому что local identity уже
  известна, а token вводится через hidden prompt. Это не alias для `repair`,
  обычного `invite/join` или штатного `node rotate`.
- Client management grammar на gateway:

```text
vpnctl client add <name> [preset...]
vpnctl client list
vpnctl client show <name-or-id>
vpnctl client revoke <name-or-id>
vpnctl client delete <name-or-id>
vpnctl client rotate <name-or-id>
vpnctl client export <name-or-id> <clash|wireguard>
```

- `client add` создаёт identity без автоматически назначенных presets. Name
  уникален, immutable ID является канонической identity. Optional positional
  preset names позволяют явно и атомарно назначить initial policy, например
  `vpnctl client add iphone telegram openai`; без дополнительных positionals
  assignment пуст. Любой unknown preset отменяет создание целиком.
- `list` показывает active и revoked records; deleted records отсутствуют.
  `revoke` применяется немедленно, требует подтверждения и не поддерживает
  `--defer`; `delete` разрешён только после revoke.
- Client-add plan не генерирует credentials и привязан к state generation,
  следующему свободному client-pool IPv4 и, при initial presets, hash полного
  source set. Commit создаёт уникальный UUID, active standard WireGuard
  transport и optional generation-1 policy одной state-транзакцией; без preset
  arguments policy отсутствует и assignment является явным пустым массивом.
- Приватный WireGuard key хранится только под owner-specific opaque secret ref.
  При доказанном pre-commit state failure staged key удаляется; при uncertain
  committed outcome он сохраняется, чтобы не оставить активную identity без
  credential. `client list/show` не имеют secret-store read dependency и не
  возвращают private/public keys, refs или profile content.
- `client show` возвращает non-secret address/assignment, credential и policy
  generation numbers, lifecycle, active transport health и export state.
  До появления artifact metadata это явное `not-exported`; `current/stale`
  подключаются в задачах export lifecycle. State-level acceptance пяти clients
  проверяет разные identity/address/credential owners; packet-level lateral
  isolation остаётся отдельной задачей 7.12.
- `rotate` сохраняет identity name и overlay IP, но требует нового export и
  ручной замены профиля. Export format является positional argument, поэтому
  отдельный `--type` отсутствует.
- `clash` export может содержать standard и restricted alternatives с ручным
  выбором пользователя внутри клиента. `wireguard` export создаёт standard
  full-tunnel profile.
- WireGuard text renderer переиспользует v1 formatter побайтно: address берётся
  из immutable client allocation, private key — только из opaque standard
  transport ref, endpoint — обязательный public gateway IPv4 на `51820/UDP`,
  gateway public key передаёт standard provider (его state относится к 8.2).
  Default DNS — `1.1.1.1, 8.8.8.8`, `AllowedIPs = 0.0.0.0/0`, keepalive `25`.
  Preset names/selectors/policy generation не являются input WireGuard export.
- Secret-bearing rendered bytes являются private полем с defensive-copy API и
  не сериализуются в JSON metadata. Запись artifact/stdout boundary остаётся в
  7.10; renderer сам не создаёт файлов.
- Client export file contract:

```text
vpnctl client export <client> <clash|wireguard> [--output <path>] [--force]

/var/lib/vpnctl/exports/clients/<name>.clash.yaml
/var/lib/vpnctl/exports/clients/<name>.wireguard.conf
```

- Export directories имеют mode `0700`, artifacts — `0600`. Managed default
  path атомарно перезаписывается при explicit re-export; custom output
  отказывается перезаписывать существующий файл без `--force`.
- Profile content никогда не печатается в stdout. Human result показывает path
  и готовую `scp` command; JSON содержит только metadata/path. Export записывает
  policy и credential generations для stale detection.
- QR, stdout piping, URL и subscription delivery отсутствуют. Revoked artifact
  может оставаться до `client delete`, но его credentials gateway уже не
  принимает.
- Policy assignment grammar:

```text
# private node: target is the current node
vpnctl policy show
vpnctl policy set <preset>...
vpnctl policy clear

# gateway: explicit personal client target
vpnctl policy show --client <name-or-id>
vpnctl policy set <preset>... --client <name-or-id>
vpnctl policy clear --client <name-or-id>
```

- `policy set` атомарно заменяет весь assignment; incremental `add/remove`
  отсутствуют. `clear` является отдельным explicit command, пустой `set` —
  validation error. Любой unknown/invalid preset отменяет операцию целиком.
- Node policy применяется сразу по умолчанию и поддерживает `--defer`. Client
  policy обновляет authoritative desired state, но не установленный профиль:
  последний Clash export помечается `stale`, а result содержит
  `requires_action: re-export`. Full-tunnel WireGuard export от preset policy не
  зависит и stale не становится.
- Gateway хранит desired node policy, а node-local state — последнее реально
  applied значение. Deferred policy меняет только gateway generation. Immediate
  policy сначала коммитит desired state, затем применяет его на node; ошибка
  локального применения оставляет явный pending result и не откатывает уже
  принятый gateway desired state. Повтор того же `set` без `--defer` применяет
  pending desired state, даже если gateway mutation уже является no-op.
- Gateway и node-local policy generations являются независимыми монотонными
  счётчиками. Связь поколений отслеживается через
  `GatewayTrust.LastKnownGatewayGeneration`; gateway generation нельзя просто
  копировать в local policy generation после нескольких deferred замен.
- Policy plan привязан к gateway state generation и hash полного набора source
  preset-файлов. Он использует только последнее effective preset-состояние и не
  активирует валидные pending edits неявно. Selected preset обязан иметь один
  валидный source; пустой/duplicate/unknown/invalid input не меняет state.
- Gateway dedicated: конфликт занятых портов или несовместимой системной
  конфигурации является preflight error, а не попыткой автоматически сосуществовать
  с произвольным nginx/Caddy/WireGuard/firewall setup.
- Основная установка — официальный curl installer с проверкой checksum.
  Обновления ручные, версии vpnctl и управляемых компонентов pinned; нужны
  проверка checksum и возможность rollback.
- Release delivery использует один signed self-contained bundle: vpnctl binary,
  manifest и pinned third-party data-plane binaries для обеих roles. Init
  устанавливает из локального bundle только components выбранной role.
- Normal apply/repair не скачивают binaries из upstream repositories. Update
  получает новый цельный bundle и сохраняет предыдущий для rollback. Bundle
  можно скачать на другой машине, передать через `scp` и установить offline;
  это не означает fully air-gapped OS setup, поскольку Ubuntu packages всё ещё
  устанавливаются из configured apt repositories.
- OS packages вроде `wireguard-tools`/`nftables` и `nginx` берутся из Ubuntu
  repositories. Mihomo, restricted transport и reverse tunnel поставляются
  через vpnctl manifest. Для bundled components `status` показывает pinned
  version/checksum; для nginx — фактическую package version и результат
  compatibility check.

### 4. Gateway, node и control plane

- Gateway хранит authoritative desired state.
- Управление остаётся server-local CLI. Remote controller с ноутбука — точка
  роста, но не scope v2.
- Команды, относящиеся к приложению или routing конкретного node, выполняются
  локально на этом node. Node передаёт intent gateway по внутреннему
  аутентифицированному протоколу.
- После join публичного management API нет. Управление идёт через защищённый
  внутренний канал.
- На gateway работает лёгкий controller. Локальный gateway CLI обращается к
  нему через Unix socket. На node отдельный постоянно работающий vpnctl-agent в
  первой итерации не нужен: CLI подключается к gateway только во время команды;
  data-plane и reverse-tunnel daemons продолжают работать независимо.
- Control plane отделён от data plane. Сбой или рестарт controller не
  останавливает уже настроенные WireGuard/restricted transports, routing,
  reverse tunnel и HTTPS ingress.
- Data-plane components запускаются отдельными systemd units с последней
  валидной конфигурацией и `Restart=on-failure`.
- После рестарта controller загружает authoritative state, но не перезапускает
  исправный data plane и не применяет автоматически `pending` operations или
  drift. Для изменения фактического состояния требуется явный `vpnctl apply`
  или `vpnctl repair`.
- Пока controller недоступен, management-команды завершаются с понятной
  ошибкой; data-plane services продолжают работу независимо.
- Любое изменение на node требует доступного gateway. Offline command queue и
  conflict resolution не поддерживаются.
- Если gateway недоступен, новая операция ничего не изменяет и возвращает
  понятную ошибку. Уже применённые routes, transports и exposes продолжают
  работать настолько, насколько позволяют существующие data-plane соединения.
- `--defer` не является offline-очередью: gateway должен быть доступен, чтобы
  зарегистрировать pending desired state.
- Post-join internal control protocol использует небольшой versioned RPC-style
  JSON contract поверх HTTPS/1.1 с mutual TLS. gRPC и собственный Noise/binary
  protocol в v2 не используются: control operations редкие, небольшие и не
  требуют streaming.
- Зафиксированные control RPC bounds: TLS 1.3 и ALPN HTTP/1.1 only, request body
  до 64 KiB, response до 256 KiB, headers до 8 KiB, JSON depth до 32,
  `2s` read-header и `5s` read-body/write/idle timeouts, не более 16 одновременно
  принятых connections. Unknown/duplicate fields, trailing JSON, wrong media
  type/path/method, oversized input/output и TLS без корректного client
  certificate отклоняются до operation dispatch.
- Control endpoint слушает только vpnctl internal overlay и не публикуется на
  public gateway interfaces. Каждая node command создаёт bounded short-lived
  connection; постоянный node agent для control plane по-прежнему не нужен.
- Control protocol имеет собственную версию `major.minor`, независимую от
  binary/release version; версия присутствует в request/response и invite.
  Minor evolution только additive/backward-compatible, breaking semantics
  требуют нового major.
- Update order — gateway-first. Новый gateway поддерживает текущий и
  непосредственно предыдущий protocol major минимум один stable release,
  чтобы старые nodes продолжали управляться во время rolling update. Node
  update до mutation проверяет gateway compatibility и отказывается
  применяться, если требуемый protocol не поддерживается.
- Protocol incompatibility возвращает явный conflict с `requires_action`
  обновить gateway/node и ничего не меняет. Уже применённый data plane при этом
  продолжает работу; устаревший protocol major удаляется только после
  предусмотренного compatibility window.
- Каждая control-plane mutation заранее получает уникальный `request_id`,
  который node сохраняет локально до definitive result, и отправляет
  `expected_state_generation`. Gateway сериализует mutations и сохраняет
  association `request_id → result/new generation`.
- Retry с тем же request ID возвращает сохранённый результат без повторной
  mutation. Запрос с устаревшей generation завершается conflict до изменений;
  vpnctl не создаёт новый request ID и не повторяет mutating intent молча.
  Read-only operations могут повторяться без idempotency record. Contract даёт
  effectively-once effects при потерянном response, но не заявляет distributed
  exactly-once delivery.
- Gateway хранит idempotency records не более 30 дней и не более 1024 последних
  mutations на node; запись удаляется при достижении любого лимита. Record не
  содержит request body, secrets или sensitive paths — только request ID,
  operation type, result status/hash и state generation. Если очень старый
  uncertain request уже evicted, vpnctl сначала reconciles resource/current
  generation и возвращает result либо conflict, но не выполняет blind retry.
- TLS transport шифрование WireGuard или Shadowsocks/ShadowTLS не считается
  control authentication boundary. mTLS identity остаётся независимой от
  active transport и связывается с immutable node ID; JSON request/response
  проходят строгую schema validation и size/time limits.
- Gateway init создаёт отдельный internal control CA, не связанный с public
  ingress certificate. Его private key хранится root-only на gateway, никогда
  не экспортируется plaintext и входит только в encrypted backup.
- Default validity internal control CA — 10 лет. Gateway control server
  certificate и per-node client certificates действуют по 5 лет. Эти сроки не
  заменяют authoritative revoke/generation checks: certificate expiration
  является дополнительной границей, а не основным lifecycle mechanism.
- Gateway control server leaf автоматически перевыпускается тем же CA за 180
  дней до expiration; node доверяет CA, а не конкретному leaf, поэтому renewal
  не требует node action и не создаёт downtime. Это не затрагивает public
  ingress certificate и его manual-only lifecycle.
- Node client certificate автоматически не обновляется. За 180 дней до
  expiration `status`/`doctor` требуют явный `vpnctl node rotate`, который
  ротирует весь согласованный node credential set. Control CA также не
  ротируется автоматически: его замена является отдельной staged operation с
  временным доверием old и new CA для всех affected nodes.
- Public ingress identity остаётся в namespace `cert`, а control CA lifecycle
  намеренно отделён в `vpnctl trust show|rotate|commit|rollback`, чтобы одна
  операция не могла неявно затронуть оба trust domains.
- Во время join node локально создаёт Ed25519 control private key и передаёт
  gateway только CSR. Выданный client certificate содержит immutable node ID в
  URI SAN; изменяемое node name не является authorization identity. Gateway
  server certificate подписан тем же control CA, а trust anchor/fingerprint
  доставляется node внутри invite.
- Control keys хранятся как PKCS#8 PEM, certificates/CSR — X.509/PKCS#10 PEM.
  Node CSR обязан иметь Ed25519 signature и ровно один canonical URI SAN
  `urn:vpnctl:node:<uuid>`; gateway строит issued SAN из authoritative ID, а не
  доверяет CN. Gateway leaf содержит `urn:vpnctl:gateway:<uuid>` и IP SAN
  внутреннего overlay address. Certificate serial — положительные случайные
  не более 128 bits.
- Enrollment response подписывается отдельным Ed25519 key по формату
  `vpnctl-enrollment-transcript-v1`: domain-separated length-prefixed frames
  связывают purpose, invite/endpoint/node IDs, issued/expiry, 128-bit nonces,
  transport, normalized presets, named public-key/CSR SHA-256 hashes и
  assignment hash. Envelope содержит algorithm, SHA-256 fingerprint DER SPKI и
  base64url transcript/signature. Допустимый clock skew — 120s; replay key
  атомарно consume'ится вместе с одноразовым invite. Invite secret остаётся
  отдельным случайным 256-bit значением.
- Controller после обычной CA validation дополнительно проверяет active node
  record и credential generation в authoritative state. Поэтому `node revoke`
  немедленно блокирует новый control request без ожидания CRL/expiration.
  `node rotate` выпускает новую mTLS generation через уже определённый parallel
  rollout; control CA не совпадает с reverse-tunnel token identity.
- Если node client certificate уже expired и обычный `node rotate` не может
  открыть mTLS channel, используется явный break-glass recovery для той же
  машины. Gateway после подтверждения создаёт привязанный к существующему
  immutable node ID одноразовый 15-minute recovery invite; token передаётся на
  private node через существующий SSH access и вводится скрыто.
- Recovery использует public token-gated endpoint на зарезервированном HTTPS
  path `443/TCP`. Private node локально создаёт новый полный credential set, а
  gateway атомарно заменяет credentials, сохраняя node name, overlay IP,
  policies и exposes. Revoked/deleted node через recovery не активируется;
  flow не поддерживает cloning identity или перенос на другую машину.

### 5. Secure node join

Happy path:

```bash
# Gateway, initial SSH session
sudo vpnctl init --gateway --public-ip 203.0.113.10

# Gateway, newly established SSH session during 120-second watchdog window
sudo vpnctl confirm <transaction-id>

# Gateway
sudo vpnctl invite bot-server

# Private node
sudo vpnctl init --node
sudo vpnctl join restricted telegram
Invite token: [hidden interactive input]

# First webhook/API expose
sudo vpnctl expose 3000 --path /telegram/webhook
```

- Этот набор зафиксирован как минимальный happy path gateway + private node.
  `init --node` не объединяется с `join`: explicit role selection и trust
  bootstrap остаются раздельными. `invite` и `join` выполняются на разных hosts
  и также не объединяются неявной remote orchestration.

- `invite <node-name>` требует явное уникальное имя node и однократно
  показывает opaque token через interactive human output.
- Отдельного `invite list` нет: active неистёкшие invites отображаются общим
  `vpnctl status` без token/secret. Для внештатной отмены используется
  `vpnctl invite cancel <invite-id>`; операция немедленно и идемпотентно
  инвалидирует только ещё не использованный invite и не требует подтверждения.
  Если invite уже использован, CLI направляет к `node revoke`.
- `join <transport> [preset...]` принимает обязательный positional transport со
  значением только `standard` или `restricted`; default отсутствует, потому что
  transport всегда выбирается вручную. Дополнительные positionals являются
  явным initial preset assignment; без них policy пуста. Любой unknown preset
  отменяет join целиком, а invite остаётся неиспользованным.
- Gateway endpoint, fingerprint и node name берутся из invite. Token вводится
  только через hidden prompt и никогда не передаётся command-line argument.
- `join` разрешён только на initialized, но ещё не joined node. Повторный join
  подключённого node ничего не меняет и направляет пользователя к manual
  `transport switch`.
- Invalid/expired invite ничего не меняет ни локально, ни на gateway. Успешный
  join сразу применяет и проверяет конфигурацию; deferred join отсутствует.
- Invite одноразовый, действует 15 минут и копируется через существующую
  доверенную SSH-сессию. Отдельное ручное сравнение fingerprint по умолчанию не
  требуется.
- Invite представлен одной opaque-строкой. В ней сериализованы версия
  протокола, public IP/endpoint gateway, fingerprint стабильной gateway
  identity, invite ID, одноразовый secret, имя node и expiration.
- Gateway хранит hash invite secret, expiration и состояние `used`, но не
  plaintext secret.
- Node генерирует private keys локально; они никогда не передаются gateway.
- Bootstrap использует token-gated HTTPS endpoint на зарезервированном path,
  например `https://PUBLIC_IP/.well-known/vpnctl/enroll`. Он может разделять
  `443/TCP` с webhook ingress, потому что это обычный HTTPS path routing.
- После успешного join invite немедленно становится недействительным, gateway
  выдаёт индивидуальные node credentials, а последующее управление переходит
  в защищённый внутренний канал.
- В первой итерации invite вводится только через скрытый interactive prompt.
  `--invite-file` не поддерживается.

### 6. Overlay addressing и routing contract

- Gateway использует два раздельных IPv4 address pools:

```text
10.66.0.0/24  personal clients (v1-compatible default)
10.67.0.0/24  private nodes
```

- Gateway автоматически выдаёт следующий свободный адрес. Logical identity
  сохраняет адрес при credential rotation; существующие v1 clients сохраняют
  свои `10.66.0.x` при миграции.
- Firewall запрещает client-to-client, client-to-node и node-to-node traffic.
  Peers могут обращаться только к явно необходимым gateway data-plane
  services и выходить через gateway в internet.
- При init оба pools проверяются на пересечение с host interfaces, routes и
  обнаруженными container networks. При конфликте init требует явно выбрать
  другой CIDR и не подбирает его через внешний сервис.
- Оба pools конфигурируемы при init, но их последующая смена является отдельной
  disruptive migration с rebind/re-export, а не обычным online apply.

- Default policy для selective routing:

```text
explicitly selected traffic → gateway
everything else             → direct
```

- Rules/presets назначаются каждому node или client только явно. Автоматическое
  назначение built-in presets запрещено.
- При установке создаётся редактируемый набор presets, как минимум `telegram`,
  `openai` и `anthropic`. Пользователь может добавлять, расширять и удалять их.
- После init presets становятся пользовательским состоянием. Upgrade никогда
  не изменяет и не восстанавливает их молча; удалённый preset остаётся
  удалённым.
- Новые версии built-in templates поставляются только внутри новой версии
  vpnctl, без remote ruleset fetching и фонового обновления. vpnctl сообщает о
  доступном template update, но изменение effective preset требует явного
  review/apply.
- При явном обновлении built-in template пользовательские additions/exclusions
  сохраняются. Если безопасный merge невозможен, preset не изменяется, а
  операция показывает conflict. Точная CLI grammar для status/diff/update
  будет определена позднее вместе со всем публичным API.
- Presets — единственная user-editable declarative часть конфигурации v2. Они
  хранятся по одному документу со стабильной публичной YAML-схемой в
  `/etc/vpnctl/presets.d/*.yaml`. Остальной desired state изменяется через CLI
  и вручную не редактируется.
- Ручное изменение preset-файла не влияет на работающую policy до явного
  validate/apply. Apply атомарно валидирует весь набор, показывает diff и все
  затронутые nodes/clients; при ошибке продолжает работать последняя валидная
  effective configuration.
- Назначенный хотя бы одному node/client preset нельзя удалить, пока он явно не
  отвязан.
- Preset grammar доступна только на gateway:

```text
vpnctl preset list
vpnctl preset show <name>
vpnctl preset validate
vpnctl preset diff
vpnctl preset update <name> [--defer]
```

- Создание/редактирование/удаление выполняются через YAML. `list` показывает
  source/effective status, assignments и available builtin update; `show` —
  normalized content и source path. `validate` всегда проверяет весь набор,
  `diff` сравнивает files с active generation.
- После ручной правки применяется общий `vpnctl apply`. `preset update`
  выполняет reviewed merge с embedded builtin template и по умолчанию сразу
  применяет результат; `--defer` обновляет YAML, оставляя effective state
  pending. Отдельных `preset add/delete/apply` нет.
- Публичная YAML-схема preset принадлежит vpnctl и близко отображает matcher
  concepts Mihomo, но не является raw Mihomo config. Preset описывает только
  selectors — какой traffic выбран — и не может задавать routing actions,
  outbound names или `DIRECT`/`PROXY`.
- Routing action остаётся системной гарантией vpnctl: совпавший selector ведёт
  в gateway либо fail-closed block, несовпавший traffic идёт direct. Одна и та
  же selector model применяется на Linux node и компилируется в экспортируемый
  Clash/Mihomo client profile.
- v2.0 поддерживает matcher subset, уже необходимый для v1-compatible exports;
  неизвестный selector type является validation error. Новые Mihomo matcher
  capabilities добавляются расширением versioned vpnctl schema.
- Preset вычисляет selected set как `include minus exclude`; внутри одного
  preset exclusion всегда имеет приоритет независимо от порядка правил.
  Excluded traffic перестаёт быть selected и поэтому следует default direct.
- Несколько назначенных presets объединяются через OR/union после локального
  вычисления каждого preset. Exclusion действует только внутри своего preset:
  явный include того же traffic другим назначенным preset снова делает его
  selected. Порядок preset-файлов и правил не влияет на результат.
- Для первой итерации достаточно selector-возможностей, уже экспортируемых v1 в
  Clash/Mihomo: прежде всего domain-suffix rules и финальный `MATCH,DIRECT`.
  Архитектура должна позволять расширение к более полной модели Mihomo.
- Personal WireGuard profile сохраняет full-tunnel behavior v1.
- DNS modes:
  - `policy` — default v2: DNS для выбранных доменов идёт через gateway, прочий
    DNS остаётся direct;
  - `direct` — compatibility mode с поведением v1.
- На private node Mihomo становится управляемым локальным DNS resolver для всей
  машины. vpnctl интегрирует его с `systemd-resolved` и перехватывает обычный
  host DNS traffic на порту 53 в пределах собственных routing/firewall
  resources. Исходная DNS configuration сохраняется и восстанавливается при
  uninstall.
- Gateway предоставляет один shared internal DNS forwarder для всех nodes и
  clients. В `policy` mode selected-domain queries идут через active transport
  к этому forwarder и далее к configured gateway upstreams; прочие queries —
  через direct path node. Отдельный DNS process на каждый node не создаётся.
- Если gateway/forwarder недоступен, selected DNS не переключается на direct;
  unrelated direct DNS продолжает работать. Смена gateway upstreams применяется
  централизованно и не требует remote node reconfiguration или client export.
- Внутренняя реализация v2 использует `redir-host` и `nameserver-policy` для
  `policy` mode; `direct` compatibility mode также использует `redir-host`, но
  без split policy. `fake-ip whitelist` отклонён: он может синтезировать ответ
  для нового selected name до обращения к gateway DNS, что расходится с
  буквальной query-path семантикой выше.
- Pinned Mihomo сохраняет ранее полученный через gateway ответ по схеме
  stale-while-revalidate: после authoritative TTL он может вернуть stale answer
  с TTL `1`, продолжая refresh только через gateway. Это не fail-direct:
  неизвестный ранее selected name при outage блокируется, direct DNS продолжает
  работать, а весь уже классифицированный selected traffic по-прежнему идёт
  через gateway либо блокируется. Cache ограничен по capacity, но не обещает
  time-based eviction во время outage; смена policy/mode очищает его restart'ом.
- Default gateway-path DNS upstreams — `1.1.1.1` и `8.8.8.8`, совместимые с
  defaults v1. Они используются только через gateway. Default direct-path
  upstreams берутся из действующей DNS configuration private node при init.
- Direct и gateway upstream lists настраиваются независимо. Между ними нет
  автоматического fallback: недоступность gateway upstream не отправляет
  selected query через direct resolver. `doctor` проверяет оба DNS paths
  отдельно.
- DNS grammar:

```text
# gateway: selected-path upstreams
vpnctl dns show
vpnctl dns set <IPv4>...
vpnctl dns reset

# private node: direct-path upstreams
vpnctl dns show
vpnctl dns set <IPv4>...
vpnctl dns reset
```

- Scope следует уже известной роли host и не повторяется аргументом: gateway
  управляет selected-path upstreams, private node — direct-path upstreams.
  Gateway `reset` возвращает defaults `1.1.1.1 8.8.8.8`; node `reset` повторно
  обнаруживает underlying system resolvers, исключая vpnctl local stub. v2.0
  принимает только IPv4 resolver addresses.
- Clash/Mihomo client export должен выражать эквивалентную split-DNS policy в
  пределах возможностей целевого клиента; расхождения capability должны быть
  видимы при export/validate, а не приводить к молчаливому ослаблению policy.
- Конкретный Mihomo DNS mode остаётся внутренней renderer detail; task 2.9
  выбрал `redir-host` по описанному выше fail-closed/query-path contract.
- Domain selectors не могут гарантированно классифицировать приложения с
  собственным DoH/DoT, hardcoded destination IP или иным скрытым resolution.
  Такой traffic остаётся unselected/direct, если он отдельно не совпал с
  IP/CIDR selector. v2.0 не пытается глобально блокировать сторонний DoH/DoT.
- Fail-closed гарантируется после классификации traffic как selected; он не
  обещает распознать скрытый домен. Это ограничение должно быть видно в
  документации и diagnostics.
- IPv4 является единственным полноценно поддерживаемым address family в v2.
  IPv6 не должен становиться обходом policy: выбранный трафик не может уйти
  direct по IPv6.
- Для любого selected UDP traffic действует fail-closed: он проходит через
  gateway либо блокируется, но никогда не переключается на direct.
- Та же fail-closed гарантия действует при недоступности gateway для всего
  явно выбранного трафика. Автоматического fail-direct нет.
- Если gateway/active transport недоступен, но local routing engine исправен,
  selected traffic блокируется, а unrelated direct traffic продолжает
  работать.
- Если сам local routing engine не готов при boot, упал или перезапускается,
  vpnctl не может безопасно классифицировать новые flows. До успешного health
  check блокируется весь новый application egress private node; аварийный
  bypass в direct запрещён.
- Уже установленные direct connections могут сохраняться только когда их
  previous direct classification надёжно закреплена conntrack mark. Отдельно
  разрешается минимальный vpnctl recovery traffic к gateway, необходимый для
  восстановления control/transport/reverse-tunnel data plane.
- Fail-closed guard активируется до routing engine и переживает его crash.
  Explicit uninstall снимает guard только в рамках контролируемого
  восстановления обычного direct networking. Цена этой гарантии — краткий
  общий downtime новых egress connections при restart local routing engine.
- На private node routing policy применяется host-wide через routing engine/TUN:
  трафик любого процесса на машине, совпавший с явно назначенным selector,
  направляется через gateway. Остальной трафик машины остаётся direct.
- Назначение policy отдельному process, Linux user, systemd unit, container или
  network namespace не входит в v2.0, но остаётся архитектурной точкой роста.

### 7. Transport contract

- `standard` transport — WireGuard. Он является окончательным выбором для
  стандартного режима и необходим для совместимости/миграции v1.
- `restricted` — технологически нейтральное обещание DPI-resistant transport.
  Shadowsocks + ShadowTLS v3 остаётся ведущим кандидатом, но должен быть
  подтверждён prototype/benchmark; это средство достижения DPI resistance, а
  не самостоятельная product feature.
- Статический compatibility spike подтвердил, что текущий Mihomo способен
  реализовать candidate stack с обеих сторон: gateway использует native
  Shadowsocks listener с ShadowTLS v3, а node и Clash-compatible client —
  Shadowsocks outbound с ShadowTLS plugin. ShadowTLS оборачивает только TCP.
- Поэтому UDP в `restricted` candidate обязан использовать Mihomo
  `udp-over-tcp`: UDP datagrams инкапсулируются во внутренний TCP stream,
  который затем целиком проходит через Shadowsocks и ShadowTLS. Native
  Shadowsocks UDP к `8443/UDP` для restricted mode не используется и должен
  быть закрыт firewall, иначе это создаст обход DPI-resistant transport.
- Для каждого selected UDP flow в `restricted` vpnctl всегда сначала пытается
  использовать этот UDP-over-TCP path. Блокировка является fail-closed
  результатом только когда restricted transport недоступен, UoT capability не
  прошла validation/health check либо packet flow нельзя обработать безопасно;
  при исправном path выбор «сразу блокировать UDP» пользователю не предлагается.
- Ошибка обязательного UoT probe означает, что `restricted` не готов: она
  проваливает `transport test restricted` и не позволяет переключить его в
  active state. Ни native UDP к gateway, ни direct fallback при этом не
  разрешаются.

```text
selected TCP ───────────────┐
                            ├─ Shadowsocks ─ ShadowTLS v3 ─ 8443/TCP ─ Gateway
selected UDP ─ UDP-over-TCP ┘
```

- Mihomo server-side listener распознаёт UoT magic destination внутри уже
  принятого Shadowsocks TCP connection и восстанавливает packet flow. Это
  подтверждает совместимость цепочки на уровне текущей реализации, но не
  заменяет live E2E test с фактической версией Mihomo внутри Clash Mi.
- UDP-over-TCP удовлетворяет fail-closed contract, но наследует TCP
  head-of-line blocking. До benchmark restricted UDP считается функционально
  поддерживаемым, но без performance guarantee для latency-sensitive voice,
  gaming и QUIC workloads.
- ShadowTLS v3 strict mode требует внешний handshake server с TLS 1.3. Это не
  пользовательский домен и не DNS name gateway: gateway проксирует настоящий
  TLS handshake к выбранному легитимному публичному host.
- Release bundle содержит небольшой versioned ordered list подходящих
  handshake hosts. Во время `init --gateway` vpnctl проверяет с gateway их
  reachability, TLS 1.3 support и latency, выбирает первый прошедший validation
  candidate и сохраняет его как явную часть authoritative state. Владеть этим
  доменом пользователю не требуется.
- Выбранный handshake host передаётся nodes через enrollment/configuration и
  включается в Clash exports. После init он остаётся pinned: runtime
  auto-rotation, fallback между hosts и автоматическая замена отсутствуют.
- `status` и `doctor` проверяют сохранённый host. Если он перестал работать,
  restricted transport получает состояние degraded и `requires_action` для
  явной ручной замены; vpnctl не меняет host самостоятельно. Это не является
  автоматическим выбором между `standard` и `restricted`: active transport
  по-прежнему выбирает только пользователь.
- Ручная замена handshake host является planned staged operation с допустимым
  коротким downtime. vpnctl сначала проверяет новый host, создаёт pending
  configuration и показывает полный список затронутых nodes и client exports;
  пользователь подготавливает обновления и затем отдельно подтверждает commit
  нового active host на gateway.
- Gateway в v2.0 обслуживает только один active handshake host. Одновременное
  SNI-demultiplexing старого и нового hosts и бесшовная migration не
  реализуются. Старый host/config сохраняется лишь в bounded rollback snapshot;
  rollback также является явной availability-impacting operation.
- После commit прежние restricted node configs и Clash exports считаются
  stale, пока не применена подготовленная configuration или не сделан новый
  export. Standard transport остаётся preferred recovery path для node.
- Если старый handshake host уже недоступен и control path через него не
  работает, operator подключается к private node по SSH и локально задаёт
  выбранный gateway host через emergency recovery flow. Host не является
  secret; существующая node identity сохраняется. Такой recovery не требует
  повторного invite/join и не открывает public management API.
- Gateway использует `vpnctl transport host show|prepare|commit|rollback`, а
  private node — emergency `vpnctl transport host recover <host>`. В каждый
  момент допускается одна staged replacement, поэтому commit/rollback не
  повторяют operation target.
- Источники статического spike:
  [Mihomo Shadowsocks outbound](https://wiki.metacubex.one/en/config/proxies/ss/),
  [Mihomo Shadowsocks listener](https://wiki.metacubex.one/en/config/inbound/listeners/ss/),
  [Mihomo UoT handling](https://github.com/MetaCubeX/mihomo/blob/Meta/listener/sing/sing.go),
  [ShadowTLS v3 protocol](https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md).
- Port layout:

```text
443/TCP   public HTTPS ingress + token-gated enrollment path
8443/TCP  restricted transport
51820/UDP standard WireGuard transport
```

- Reverse proxy принимает HTTPS на `443/TCP`; restricted transport обслуживает
  отдельный listener/backend на `8443/TCP`. HTTP path routing не используется
  для multiplexing произвольного DPI-resistant protocol.
- Gateway устанавливает и держит готовыми оба transport listeners.
- Transport для каждого node/client выбирается только вручную. Automatic
  detection, automatic fallback и runtime auto-switch отсутствуют.
- При join node получает отдельные credentials для обоих transports. Один
  отмечается `active`, второй хранится настроенным как `standby`.
- В steady state один active transport node используется для всех flows между
  node и gateway: vpnctl control traffic, multiplexed reverse tunnel и selected
  egress. Обычный direct traffic node остаётся вне него.
- Transport grammar доступна только на private node:

```text
vpnctl transport test <standard|restricted>
vpnctl transport switch <standard|restricted> [--defer]
```

- Отдельного `transport status` нет: active/standby и health показывает общий
  `vpnctl status`. На gateway transport endpoints всегда включены, поэтому
  `enable/disable` commands отсутствуют. Personal client переключается вручную
  внутри Clash/Mihomo profile.
- `transport test` временно поднимает и проверяет target transport, включая
  control, reverse tunnel и TCP/UDP probes, затем удаляет test connection и не
  меняет production routing.
- `transport switch` выполняет make-before-break:
  устанавливает target connection, переносит control path, поднимает новый
  reverse tunnel, проверяет его, переключает selected traffic, даёт старым
  requests завершиться и только после подтверждения отключает старый
  transport/tunnel. Во время switch два соединения могут существовать временно.
- Ошибка switch оставляет старый transport active. Switch на уже active target
  идемпотентен и выполняет health check. `--defer` регистрирует pending target;
  фактическое переключение выполняет последующий `vpnctl apply` на node.
- Если active transport уже заблокирован, node может поднять standby из
  сохранённых credentials. Команда успешна только после связи с gateway.
- Для Clash/Mihomo client profile могут экспортироваться оба варианта, но
  фактический выбор пользователя остаётся ручным.

### 8. Managed HTTPS ingress

- Scope v2: HTTP/HTTPS webhooks и обычные API requests. Generic TCP/UDP ingress,
  WebSocket, SSE, gRPC и специальные streaming guarantees не входят в первую
  итерацию, но модель не должна закрывать их дальнейшее добавление.
- `vpnctl expose` выполняется на private node:

```bash
vpnctl expose 3000
vpnctl expose 3000 --path /telegram/webhook
vpnctl expose 127.0.0.1:3000
vpnctl expose 127.0.0.1:3000 --path /telegram/webhook
vpnctl expose 127.0.0.1:3000 --path /api/ --prefix
vpnctl expose list
vpnctl expose show <name-or-id>
vpnctl expose remove <name-or-id>
```

- Upstream positional argument принимает port-only shorthand (`3000`), который
  нормализуется в `127.0.0.1:3000`, либо полную форму `host:port`. Numeric port
  и `host:port` не конфликтуют с management verbs `list/show/remove`. Optional
  `--name` задаёт уникальное внутри node human name; иначе используется
  immutable ID.
- Без `--path` генерируется high-entropy exact path. `--prefix` явно включает
  prefix matching для указанного path.
- Non-loopback upstream требует `--allow-non-loopback` и предупреждения.
  Успешное создание показывает human-only public URL, certificate path и
  status. Создание и удаление поддерживают `--defer` и требуют доступный
  gateway.
- `expose remove` требует подтверждения и возвращает `requires_action` для
  удаления внешней webhook registration.

- Public ingress v2.0 работает только в IP-only mode. Domain/ACME support не
  входит в первую итерацию, но остаётся архитектурной точкой расширения.
  Рабочий endpoint:

```text
https://PUBLIC_GATEWAY_IP/telegram/webhook
```

- vpnctl генерирует и сохраняет стабильный self-signed public ingress
  certificate для public IP, отдаёт путь к публичной части сертификата и
  итоговый webhook path/URL. Владелец приложения сам регистрирует webhook и
  передаёт сертификат внешнему API при необходимости.
- Gateway identity для join/control и public ingress certificate являются
  отдельными логическими identities/keys. Будущий domain certificate сможет
  выпускаться и обновляться независимо, не меняя fingerprint/trust nodes.
- Public ingress certificate является долгоживущим и не ротируется
  автоматически, потому что vpnctl не управляет внешними webhook
  registrations, доверяющими старому сертификату.
- Default lifetime public ingress certificate — пять лет. Это уменьшает
  необходимость ручной перерегистрации webhook; default остаётся условным до
  Telegram E2E compatibility spike. `status` и `doctor` заранее предупреждают
  об истечении, а rotation по-прежнему выполняется только явно.
- Криптографический профиль public ingress certificate в v2 фиксирован:
  RSA-2048 key и подпись SHA-256. Public IPv4 gateway присутствует в IP-type
  `subjectAltName` и для консервативной совместимости дублируется в `CN`.
  Private key хранится только в root-readable state и не экспортируется командой
  `cert export`.
- Официальная Telegram webhook documentation подтверждает IP-only flow:
  Telegram поддерживает IPv4 webhook endpoint с self-signed certificate,
  `443/TCP`, TLS 1.2+ и требует загрузить public certificate в PEM как
  multipart `InputFile` при `setWebhook`. Certificate должен идентифицировать
  тот же public IP; vpnctl генерирует IP в SAN и, для консервативной
  совместимости, также в CN.
- Public HTTPS ingress принимает только TLS 1.2 и TLS 1.3. TLS 1.0/1.1 и иные
  устаревшие версии отключены; client mTLS не требуется, поскольку внешние
  webhook providers вроде Telegram его не предоставляют, а application-level
  authentication остаётся ответственностью опубликованного приложения.
- На public ingress nginx принимает HTTP/1.1 и HTTP/2 через ALPN; для HTTP/2
  действует жёсткий bounded limit concurrent streams. Внутренний proxy hop
  nginx → frp → application использует HTTP/1.1. HTTP/3/QUIC и `443/UDP` не
  поддерживаются в v2; WebSocket upgrade также не входит в обещанный
  webhook/API request contract и остаётся точкой роста.
- Source verification:
  - https://core.telegram.org/bots/webhooks
  - https://core.telegram.org/bots/api#setwebhook
- `status`/`doctor` предупреждают о приближении certificate expiration.
  Rotation запускается только вручную, показывает все затронутые exposes,
  выдаёт новый public certificate и `requires-action` список внешних webhook
  registrations, которые необходимо обновить. При rotation допустим краткий
  downtime.
- Пятилетний certificate lifetime должен быть подтверждён compatibility spike
  с целевыми webhook providers, прежде всего Telegram Bot API; при обнаружении
  ограничения корректируется default, но не manual-only rotation contract.
- vpnctl не вызывает Telegram Bot API, не хранит bot token и не отвечает за
  lifecycle приложения.
- TLS завершается на gateway. Path и query string сохраняются без переписывания
  при передаче приложению.
- Несколько exposes разделяют один `443/TCP` через разные paths. Path matching
  поддерживает `exact` по умолчанию для webhook и явный `--prefix` opt-in для
  API subtree.
- Ambiguous/overlapping routes отклоняются. Prefix
  `/.well-known/vpnctl/` зарезервирован для внутренних endpoints и недоступен
  пользовательским exposes.
- Пользователь может задать path явно; vpnctl также может сгенерировать
  уникальный high-entropy path. Path не считается механизмом authentication.
  Проверка Telegram secret token и иная application authentication остаются
  ответственностью приложения; vpnctl передаёт соответствующие application
  headers upstream, но не логирует их.
- vpnctl предоставляет bounded reverse proxy, но не становится application API
  gateway. Он применяет безопасные header/read/idle/upstream timeouts, limits
  на headers/request body и global connection concurrency и передаёт body
  потоково без полного buffering в RAM. Точные defaults определяются
  benchmark/Telegram compatibility spike и остаются конфигурируемыми.
- Ingress limits имеют два уровня. Gateway hard limits задают общий предел
  concurrent connections/requests, максимальный размер headers и абсолютные
  верхние границы request body/timeouts; отдельный expose не может их обойти.
  Каждый expose получает safe defaults и может явно менять разрешённые
  параметры, как минимум body size и upstream timeout, только в пределах hard
  limits. Per-IP rate limiting и WAF не входят в v2.
- Пользователь не может передавать raw nginx directives. Authoritative expose
  state хранит только стабильные implementation-neutral параметры; vpnctl
  валидирует их и генерирует nginx configuration как производный артефакт.
- Reverse proxy работает отдельным от vpnctl controller data-plane process.
  Основной implementation candidate v2 — `nginx` из Ubuntu 24.04 repositories:
  vpnctl устанавливает package, полностью владеет его generated configuration и
  systemd service override, проверяет конфигурацию до применения и выполняет
  graceful reload. Пользовательское редактирование managed nginx-конфигурации
  не поддерживается.
- nginx выбран вместо предварительного кандидата Caddy потому, что текущей
  IP-only v2 важнее предсказуемое потребление ресурсов и штатные streaming/body/
  connection limits на host с 1 vCPU/512 MB. Выбор условен до resource и E2E
  prototype; если nginx не проходит acceptance gates, Caddy остаётся fallback.
  Domain/ACME остаётся архитектурной точкой расширения: authoritative ingress
  model не содержит nginx-specific primitives, а generated proxy config является
  заменяемым производным артефактом.
- Недоверенные входящие forwarding headers очищаются; vpnctl формирует
  доверенные proxy headers из фактического соединения. Unknown path возвращает
  `404`, недоступный tunnel/upstream — `503`, upstream timeout — `504`.
- Gateway является stateless forwarding layer для application traffic: он не
  ставит webhook/API requests в очередь, не сохраняет request bodies на диск и
  не повторяет запрос к upstream после transport/tunnel failure. Retry и
  delivery semantics остаются ответственностью внешнего provider и приложения.
- Если tunnel/upstream недоступен до начала downstream response, gateway
  возвращает `503`. Если upstream уже начал response и затем соединение
  оборвалось, gateway завершает downstream connection: заменить уже начатый
  response новым HTTP status технически невозможно.
- Восстановление tunnel влияет только на новые requests. Потерянный или
  оборванный request vpnctl после reconnect не воспроизводит; это исключает
  неявные дубликаты non-idempotent webhook/API calls и bounded-storage
  subsystem на gateway.
- Application authentication, Telegram secret-token validation, WAF,
  CAPTCHA, application allowlists и per-user/per-IP rate limiting не входят в
  v2 и остаются ответственностью опубликованного приложения.
- Если локальное приложение не запущено, expose всё равно может быть создан со
  статусом `degraded`; gateway возвращает `503`, пока upstream недоступен.
- На каждый node используется одно постоянное multiplexed reverse-tunnel
  соединение и один root-only набор per-node tunnel credentials. Tunnel
  identity независима от WireGuard и Shadowsocks/ShadowTLS credentials:
  переключение или rotation transport не пересоздаёт tunnel identity.
- Gateway аутентифицирует tunnel identity и связывает её с immutable node ID;
  node может объявлять только принадлежащие ему expose mappings и не может
  представиться другим node внутри общей overlay-сети. `node revoke` отзывает
  transport, control и tunnel credentials этой identity.
- Каждый `expose` — отдельный логический resource/stream mapping, но не
  отдельный daemon, connection или постоянный secret. Дополнительная tunnel
  identity означает только один key/PSK set и handshake на persistent
  connection, а не credentials на каждый expose.
- После разрыва node-side tunnel daemon пытается восстановить persistent
  connection бесконечно с bounded exponential backoff и jitter; ручной restart
  systemd unit для обычного восстановления не требуется. Reconnect использует
  только текущий active transport и никогда самостоятельно не пробует standby.
- Новый connection становится ready только после успешной per-node
  authentication, сверки configuration generation и проверки зарегистрированных
  mappings/local upstreams. До этого все exposes node остаются `degraded`, а
  gateway возвращает `503`; после readiness новые requests проходят без
  ручного enable.
- Ведущий implementation candidate — pinned `frp`: один shared `frps` на
  gateway и один `frpc` на private node. `tcpMux` включён, connection pool
  выключен; несколько expose streams одного node проходят через одно
  persistent transport connection.
- `frpc` configuration обновляется атомарно и применяется через loopback-only
  dynamic reload. Gateway controller использует frp server-plugin hooks
  `Login` и `NewProxy`, чтобы связать connection с immutable node ID и разрешить
  только mappings, уже присутствующие в authoritative vpnctl state.
- Внутренний frp connection всегда использует TLS с проверкой gateway
  certificate, даже когда проходит внутри уже encrypted active transport. Для
  tunnel authentication каждый node получает отдельный случайный 256-bit
  symmetric token; встроенный общий frp server token не считается per-node
  identity boundary.
- `frpc` передаёт immutable node ID и tunnel token в TLS-protected metadata.
  Gateway controller проверяет их на `Login`, а на `NewProxy` дополнительно
  сверяет proxy name, type и loopback remote port с authoritative expose state.
  Отдельный frps process, OIDC provider или public plugin endpoint для каждого
  node не создаются.
- Tunnel token хранится только в root-readable state и никогда не попадает в
  human/JSON status, application logs, client exports или unencrypted backup.
  Controller plugin endpoint доступен только локальному frps и редактирует
  secrets во временной diagnostic output. `node revoke` закрывает текущий
  frp connection и немедленно инвалидирует token для reconnect.
- frps слушает только vpnctl internal overlay, его dashboard/UI, P2P, public
  HTTP routing и неиспользуемые proxy types отключены. Public ingress по-прежнему
  принимает bounded reverse proxy vpnctl на `443/TCP`; frp public listeners не
  экспозятся.
- `rathole` исключён из v2 candidate stack: несмотря на низкое потребление
  ресурсов и hot reload, его текущая архитектура не предоставляет требуемое
  stream multiplexing и создаёт отдельные work connections. OpenSSH reverse
  forwarding остаётся fallback candidate, если frp не пройдёт security/resource
  prototype, но потребует больше собственной orchestration logic.
- Выбор frp не является публичным API и остаётся условным до benchmark на
  Ubuntu 24.04, 1 vCPU/512 MB и проверки dynamic add/remove, reconnect,
  per-node authorization и transport switch.
- Источники static comparison:
  [frp stream multiplexing](https://gofrp.org/en/docs/overview/),
  [frp dynamic reload](https://gofrp.org/en/docs/features/common/client/),
  [frp server plugins](https://gofrp.org/en/docs/features/common/server-plugin/),
  [rathole capabilities](https://github.com/rathole-org/rathole).
- Для каждого expose gateway controller автоматически выделяет отдельный
  stable-for-lifetime internal TCP endpoint из vpnctl-managed port range.
  frps bind выполняется только на `127.0.0.1:<managed-port>`, а bounded reverse
  proxy направляет соответствующий public path на этот endpoint.
- Managed port не является частью public expose API, не вводится пользователем
  и обычно виден только в detailed diagnostics. Gateway firewall его наружу не
  открывает; allocation проверяет collision и exhaustion до commit.
- При `expose remove` новые requests перестают маршрутизироваться, текущие
  streams получают bounded drain period, затем frp mapping удаляется и port
  возвращается allocator. Restore сохраняет allocation, если она свободна, или
  атомарно переназначает endpoint вместе с reverse-proxy config до публикации.
- Создание expose не открывает входящий порт на private node: reverse tunnel
  устанавливается исходящим соединением node к gateway.
- По умолчанию local upstream expose должен быть доступен через loopback,
  например `127.0.0.1:3000`. Адрес из non-loopback interface или container
  network допускается только как явный opt-in с предупреждением; vpnctl не
  перепривязывает приложение и не меняет его firewall автоматически.
- Удаление одного expose не влияет на другие. `node revoke` закрывает tunnel и
  все exposes этого node.

### 9. Desired state, apply и recovery

- По умолчанию mutating commands применяются сразу.
- Поддерживаются preview/delayed flows: `--dry-run`, `plan`, `--defer`, `apply`.
- Operational grammar и границы действий:

```text
vpnctl status
vpnctl doctor
vpnctl plan
vpnctl apply
vpnctl repair
```

- `status` — passive snapshot без probes; `doctor` — явные active probes без
  mutation; `plan` — diff pending desired state и отдельно detected drift;
  `apply` — convergence только зарегистрированных pending changes; `repair` —
  explicit reconciliation vpnctl-owned drift после preview и подтверждения.
- Drift в ресурсе, который должен изменить apply, является conflict: apply не
  перезаписывает его и направляет к repair. Repair никогда не изменяет unknown
  external resources.
- `--dry-run` у mutating command моделирует только эту ещё не
  зарегистрированную operation. `--defer` регистрирует pending desired change,
  с которым затем работают общий `plan/apply`.
- На private node `apply/repair` scoped к текущему node и требуют gateway; на
  gateway они изменяют только gateway-side resources и не имитируют отсутствующий
  remote node agent.
- Drift обнаруживается, но vpnctl не перезаписывает неизвестные изменения без
  явного `repair`.
- Локальное применение на одном host транзакционно: validate, stage, atomic
  activation, health check, rollback локального изменения при подтверждённой
  ошибке.
- Между двумя hosts используется convergent transaction, потому что строгая
  distributed atomicity невозможна:

```text
validate → stage → activate → confirm
```

- Операция имеет уникальный ID и состояния как минимум `pending`, `active`,
  `degraded`, `failed`.
- Для ingress публичный path активируется последним, после готовности tunnel.
- Если связь оборвалась и итог неизвестен, vpnctl не выполняет blind rollback.
  Операция остаётся `pending`; следующий `status`/`apply` сверяет generation и
  фактическое состояние, затем продолжает движение к новому desired state.

#### Diagnostics contract

- `vpnctl status` является passive/read-only командой: читает desired state,
  systemd/listener state, generation, config hashes и доступные last-handshake
  данные, но не создаёт synthetic traffic и ничего не изменяет.
- Status grammar:

```text
vpnctl status
vpnctl status --all
vpnctl status --json
```

- Default human output показывает role/versions/overall health, gateway/control
  connectivity, active transport/data-plane health, resource counts, pending,
  drift, active invites/log opt-ins, certificate/backup warnings и только
  проблемные resources с `requires_action`. `--all` разворачивает все resource
  tables; JSON всегда содержит full structure независимо от `--all`.
- Exit code success сохраняется для healthy state с warnings или намеренно
  deferred pending changes. Фактический degraded/failed component, drift или
  mandatory dependency unavailable возвращает degraded/unavailable category;
  unreadable/invalid state — отдельную error category.
- `vpnctl doctor` запускается только вручную и является явным временным opt-in
  на active diagnostic traffic. Он выполняет безопасные DNS, TCP, UDP, TLS,
  transport и reverse-tunnel probes и проверяет local upstream каждого expose.
- Doctor grammar:

```text
vpnctl doctor
vpnctl doctor <dns|transport|tunnel|ingress>
vpnctl doctor --probe-url <https-url>
```

- Без scope выполняется bounded suite для текущей role. Каждый probe имеет
  timeout и общий deadline. `dns` независимо проверяет direct/gateway paths;
  `transport` — только active transport (standby проверяет `transport test`);
  `tunnel` — internal multiplexed ping.
- `ingress` проверяет public-IP TLS, reserved internal health path, tunnel и
  local upstream connectivity, но никогда автоматически не вызывает реальные
  webhook paths. Только explicit `--probe-url` разрешает безопасный `GET` без
  body/credentials к указанному user endpoint.
- `SKIPPED` не является failure; failed mandatory probe возвращает degraded
  exit category. Doctor никогда не выполняет repair, apply или transport switch.
- `doctor` остаётся read-only относительно конфигурации: не переключает
  transport, не выполняет apply/repair и не регистрирует внешние webhooks.
- Diagnostic probes не отправляют request bodies и sensitive paths. Они могут
  обращаться только к собственным gateway/nodes, configured upstreams, явно
  выбранным service domains или target, переданному через `--probe-url`.
- vpnctl не использует скрытый project-operated telemetry/probe endpoint. Если
  конкретную проверку нельзя выполнить без неизвестного внешнего сервиса, она
  получает результат `SKIPPED` с объяснением.

### 10. State layout

- В v2 state больше не зависит от current working directory.
- Первая итерация использует system-owned JSON state без SQLite:

```text
/etc/vpnctl/
  presets.d/
    *.yaml

/var/lib/vpnctl/
  state.json
  secrets/
  exports/

/run/vpnctl/
  control.sock
```

- Gateway controller — единственный writer authoritative state. Операции
  сериализуются. User-edited preset files являются входными декларациями;
  controller сохраняет в authoritative state их нормализованную effective
  representation, hash и generation только после успешного explicit apply.
- Надёжная запись: validate → temporary file → fsync → atomic rename.
- State содержит монотонную `generation`; сохраняется как минимум одна
  предыдущая версия для локального rollback.
- Secrets хранятся отдельно с root-only permissions (`0600`, directory `0700`)
  и не шифруются at rest. Шифруются backup archives.
- Обычное ручное редактирование state не является supported workflow.
  Break-glass edit возможен после остановки controller с обязательными
  `vpnctl validate` и `vpnctl repair`.

### 11. Host и firewall ownership

- Gateway находится в исключительном функциональном владении vpnctl: утилита
  задаёт поддерживаемую сетевую конфигурацию, резервирует порты, управляет
  forwarding/NAT/firewall policy и не поддерживает размещение сторонних
  приложений или reverse proxies.
- Полное функциональное владение не означает безусловное удаление неизвестного
  системного состояния. vpnctl не выполняет `nft flush ruleset` и не удаляет
  provider-managed или иные чужие firewall tables.
- Firewall backend v2 — `nftables`. vpnctl управляет отдельной таблицей,
  например `inet vpnctl`, и полностью владеет созданными в ней chains, sets и
  rules.
- vpnctl-owned resources создаются, изменяются и удаляются утилитой. Unknown
  external resources не изменяются. При конфликте init/apply завершается
  fail-closed ошибкой с перечнем необходимых ручных действий.
- Таблица vpnctl реализует default-deny для unsolicited inbound, разрешает
  established/related traffic, loopback, обнаруженный SSH port и только
  необходимые vpnctl listeners; также содержит принадлежащие vpnctl forwarding
  и NAT rules.
- SSH port detection является fail-closed. Explicit `--ssh-port` проверяется
  против фактического sshd/systemd listener. Без override vpnctl берёт server
  port текущего `SSH_CONNECTION`, сверяет его с listener и показывает port и
  detection source в plan. Если команда запущена не через SSH, listeners
  неоднозначны или источники расходятся, vpnctl не предполагает port `22`, а
  останавливается до mutation и требует явный `--ssh-port`.
- В v2 обнаруженный SSH port разрешён с любого IPv4 source (`0.0.0.0/0`).
  vpnctl не привязывает доступ к IP текущей сессии, поскольку адрес владельца
  может измениться или находиться за NAT/bastion. Утилита не меняет
  `sshd_config`, SSH keys или password authentication; небезопасные настройки
  могут давать warning, но их исправление остаётся ответственностью владельца.
  Configurable SSH source CIDRs остаются backlog item.
- Активный UFW/firewalld или несовместимые внешние rules являются preflight
  conflict, а не автоматически поддерживаемой coexistence-конфигурацией.
- UFW-конфигурация v1 обрабатывается отдельным one-time migration script.
- Операции, способные заблокировать management access, используют обязательный
  rollback watchdog. К ним относятся как минимум первоначальное включение
  gateway default-deny при `init`, смена SSH port/external interface и иные
  firewall/routing plans, явно классифицированные как lockout-risk.
- До mutation vpnctl сохраняет предыдущий vpnctl-managed network state и
  запускает host-level watchdog, независимый от жизни CLI/controller process.
  Новый ruleset применяется атомарно, но transaction остаётся uncommitted до
  явного подтверждения сохранённого SSH-доступа. Если подтверждение не получено
  за bounded timeout, process аварийно завершился или post-apply checks не
  прошли, watchdog восстанавливает предыдущие vpnctl rules/routes/sysctls.
- Сохранение исходной SSH-сессии не является подтверждением: established
  connection может продолжать работать при заблокированных новых SYN. Исходная
  session остаётся открытой и показывает countdown, а пользователь создаёт
  вторую SSH-сессию уже после mutation и выполняет в ней показанную vpnctl
  confirm operation с transaction ID. Только это завершает commit и отменяет
  watchdog; если новый login невозможен, пользователь ничего не подтверждает и
  ожидает автоматического rollback.
- `--yes` не обходит connectivity confirmation: это проверка доступности, а не
  consent prompt. Обычные `expose`, policy и credential operations, которые не
  меняют SSH/firewall/routing boundary, watchdog confirmation не требуют.
- Watchdog timeout в v2 фиксирован на 120 секунд и не имеет public CLI override.
  По истечении transaction откатывается; повторная попытка создаёт новую
  transaction с новым полным timeout. Финальная CLI grammar подтверждения будет
  определена вместе с command-tree review; recovery должна работать без
  controller и не изменять чужие firewall tables.
- Такое разделение является границей безопасного управления и удаления, а не
  ослаблением dedicated-gateway contract.
- Private node, в отличие от gateway, является application host и не переходит
  в исключительное владение vpnctl. На нём сохраняются пользовательские
  приложения и иные несвязанные services.
- На private node vpnctl владеет только собственными файлами, systemd units,
  transport/TUN/routing resources, nftables table/chains и reverse tunnel.
  Host-wide routing означает применение выбранной policy ко всем процессам,
  но не даёт vpnctl право управлять остальной конфигурацией машины.
- vpnctl не изменяет чужие applications, Docker configuration, systemd units,
  listeners или firewall rules и не вводит для private node глобальный
  default-deny на unrelated inbound traffic.
- При конфликте чужой firewall/routing/TUN configuration с необходимыми
  vpnctl resources операция завершается до изменения либо остаётся в явно
  диагностируемом состоянии; vpnctl показывает конфликт, но не переписывает
  чужую конфигурацию автоматически.

### 12. Security, logging и lifecycle

- Node/client credentials уникальны. Revoke применяется немедленно; delete —
  отдельная операция.
- Lifecycle node является двухэтапным и не зависит от доступности самого node:
  - `revoke` — security operation на authoritative gateway. Она немедленно
    инвалидирует все credentials node, закрывает его transports и reverse
    tunnel, отключает все exposes, но сохраняет запись и диагностический
    контекст;
  - `delete` — последующая cleanup operation, разрешённая только для уже
    revoked node. Она удаляет gateway-side configuration, exposes и сохранённые
    данные node, но не предполагает удалённого доступа к private VPS.
- При штатном detach online-node сначала запрашивает revoke у gateway и только
  после подтверждения очищает локальные vpnctl runtime resources. При
  потерянном/скомпрометированном/offline node владелец выполняет revoke локально
  на gateway; возвращённый в сеть node со старыми credentials подключиться не
  может.
- Локальный uninstall node при недоступном gateway может остановить и удалить
  node-side runtime, но не считается отзывом доступа. Он обязан вывести
  `requires-action` с требованием отдельно выполнить gateway-side revoke.
- Lifecycle client также двухэтапный:
  - `revoke` немедленно инвалидирует client credentials на gateway; уже
    сохранённый профиль перестаёт подключаться, но vpnctl не может физически
    удалить его с пользовательского устройства;
  - `delete` разрешён только после revoke и удаляет gateway-side client record
    и сохранённые export-файлы.
- Повторное создание client с тем же именем всегда выпускает новую identity и
  credentials. Rotation также выпускает новые credentials и требует нового
  export и ручной замены профиля на устройстве.
- Rotation запускается только вручную. Для node используется параллельная
  выдача новых credentials и переключение без разрыва при нормальной работе;
  для client требуется повторный export config.
- Logging выключен по умолчанию. Любое расширенное логирование требует явного
  временного opt-in со scope, level и duration; запись в дополнительный
  destination также включается отдельно.
- Logging grammar:

```text
vpnctl log status
vpnctl log enable <scope> --level <level> --for <duration> [--file <path>]
vpnctl log disable <scope|all>
```

- Scopes v2: `control`, `transport`, `routing`, `dns`, `tunnel`, `ingress`,
  `all`; levels: `error`, `info`, `debug`, `trace`. Scope, level и duration
  обязательны, одна session ограничена максимум одним часом.
- Expiration автоматически отключает logging и переживает service/controller
  restart как абсолютное время окончания. `log status` показывает только
  active opt-ins и remaining time.
- Default destination opt-in session — journald. Дополнительный file требует
  отдельного `--file`, создаётся с mode `0600` и bounded size rotation. Remote
  log destinations отсутствуют.
- Secrets, authorization headers, request/response bodies и webhook paths не
  логируются даже в diagnostic mode.
- Telemetry и автоматические remote calls отсутствуют.
- Portable backup/restore обязателен только для gateway. Passphrase-encrypted
  archive включает authoritative state, presets, gateway identities и
  certificates, client secrets/exports и gateway-side material, необходимый
  для продолжения доверия к существующим nodes.
- Node private keys никогда не включаются в gateway backup и не извлекаются с
  node. Потерянный private node восстанавливается через revoke старой identity
  и join новой машины; backup/restore или cloning node identity не входит в
  v2.0. User applications и их данные также не входят в backup vpnctl.
- Portable backup запускается только вручную. Passphrase вводится и
  подтверждается через hidden interactive prompt; command-line argument для
  passphrase в v2.0 запрещён. vpnctl не устанавливает backup timer, не хранит
  encryption key на gateway и не загружает архив во внешнее storage.
- Архив записывается атомарно с mode `0600`; существующий target молча не
  перезаписывается. Пользователь забирает файл через `scp`. `status` показывает
  отсутствие или давность последнего успешного backup; точный warning threshold
  является настраиваемым default, который будет выбран при CLI/defaults design.
- Backup/restore grammar на gateway:

```text
vpnctl backup [archive-path]
vpnctl restore <archive-path> --public-ip <IPv4> [--replace]
```

- Без output path backup создаёт timestamped archive в
  `/var/lib/vpnctl/backups/`. Restore всегда требует вручную переданный public
  IP, даже если он не изменился, и не берёт endpoint молча из archive.
- На clean installed host restore сам устанавливает gateway role; предварительный
  init не требуется. Archive полностью decrypt/validate и host preflight
  выполняются до mutation. Restore никогда не merge-ит два states.
- На initialized gateway restore по умолчанию отказывается работать.
  `--replace` показывает impact, создаёт emergency snapshot текущего managed
  state, останавливает controller и выполняет atomic replacement.
- Restore gateway при неизменном endpoint должен сохранять работоспособность
  существующих nodes и client profiles. Pre-update local snapshots служат
  только rollback текущей машины и не считаются portable backup.
- Restore на gateway с новым public IP допустим, но не seamless. vpnctl выводит
  `requires-action` список: rebind nodes, re-export clients, повторно
  зарегистрировать webhook URLs и выполнить другие необходимые внешние шаги.
- Удаление разделено на две операции по модели package remove/purge:
  - `vpnctl uninstall` показывает impact plan, останавливает и удаляет
    vpnctl-managed runtime resources и в конце удаляет установленный стандартным
    installer бинарник, но сохраняет `/var/lib/vpnctl`,
    `/etc/vpnctl/presets.d`, identities, secrets, certificates и backups для
    последующего восстановления;
  - `vpnctl purge` сначала выполняет uninstall, затем необратимо удаляет state,
    presets, credentials, certificates и exports, требует typed confirmation и
    показывает список внешних последствий. Portable `.backup` archives
    сохраняются по умолчанию; их удаление требует отдельного
    `--include-backups` и второго typed confirmation.
- Online node uninstall сначала получает подтверждение gateway-side revoke и
  затем удаляет local runtime. При недоступном gateway обычная операция
  останавливается; `vpnctl uninstall --local-only` явно разрешает cleanup и
  возвращает обязательный gateway revoke в `requires_action`.
- Gateway с active nodes/clients/exposes требует
  `vpnctl uninstall --force` после полного impact plan. Binary всегда удаляется
  последним.
- Gateway uninstall не должен молча разрушать active nodes, clients или
  exposes: перед выполнением vpnctl показывает их список и требует явного
  подтверждения/force semantics. Удалённые с gateway клиентские конфиги и
  зарегистрированные webhook URLs vpnctl физически отозвать не может, поэтому
  сообщает необходимые последующие действия.

### 13. Delivery, migration и capacity

- Обновления выполняются только вручную и последовательно в порядке
  `gateway → nodes`; vpnctl никогда не обновляет remote nodes автоматически.
- Software update grammar:

```text
vpnctl update
vpnctl update <version>
vpnctl update rollback
```

- Без version выбирается latest stable release; explicit version устанавливает
  конкретную compatible release. Beta/nightly channels и background checks в
  v2.0 отсутствуют: network request выполняется только после ручного `update`.
- До остановки services проверяются signed/checksummed version manifest,
  vpnctl binary и pinned managed-component bundle. Затем показываются version
  diff, fleet compatibility, state migrations и rollback capability; update
  требует подтверждения и не поддерживает `--defer`.
- `update rollback` восстанавливает previous binary/component bundle и state
  snapshot только если применённая migration сохранила backward compatibility.
  Если rollback станет невозможен, update сообщает это до применения и требует
  отдельного подтверждения.
- Binary version и internal protocol version не отождествляются. Для control
  protocol gateway поддерживает текущий и непосредственно предыдущий protocol
  major минимум один stable release; minor evolution additive/backward-
  compatible. Data-plane/config compatibility проверяется отдельно по manifest
  конкретных components. Это bounded window, а не бессрочная совместимость.
- Node новее gateway не применяется: node update завершается на preflight.
  Gateway update по умолчанию также останавливается, если среди active nodes
  есть версии старше поддерживаемого окна.
- Management version mismatch не должен разрушать уже работающий совместимый
  data plane. Unsupported mutation возвращает `upgrade-required`, не меняя
  конфигурацию.
- Перед update сохраняются previous binary/component versions и state snapshot.
  Plan показывает fleet compatibility и rollback capability. Необратимая state
  migration требует отдельного подтверждения и явно сообщает об ограничении
  rollback.
- Update только controller/vpnctl binary не перезапускает исправный data plane.
  Изменившиеся data-plane components обновляются последовательно с per-service
  health check и rollback; неизменившиеся components не трогаются.
- На single-host gateway zero-downtime update не обещается. Возможны краткий
  reconnect transport, временный ingress `503` и обрыв active request. Restart
  local routing engine использует согласованный fail-closed guard. Update plan
  заранее перечисляет затрагиваемые components и ожидаемый interruption.
- Основной способ получить client config — локальный export на gateway и `scp`.
- QR, URL delivery, temporary/signed links и subscription links не входят в
  первую итерацию и остаются backlog growth points.
- Миграция с v1 обязательна, но реализуется отдельным one-time migration script,
  а не постоянной командой основного vpnctl.
- Миграция сохраняет client keys, allocated IPs и экспортируемые profiles,
  насколько это технически возможно. Краткий downtime допустим.
- Целевая минимальная gateway VPS: `1 vCPU`, `512 MB RAM`, `10 GB disk`.
  Начальная нагрузка: один основной private node с Telegram API/webhook для
  нескольких сотен пользователей и до пяти personal clients.
- Native shared daemons предпочтительнее отдельного процесса на каждый
  resource. Потребление controller в idle должно быть небольшим и проверяться
  benchmark; ориентир — не более примерно `20 MiB`.
- На gateway с RAM меньше `1 GiB` и суммарным swap меньше `1 GiB` vpnctl
  предлагает создать управляемый `1 GiB` swap после показа plan и отдельного
  явного yes/no выбора. Отказ от swap не отменяет init; `--yes` принимает и
  optional swap, и обычное подтверждение init. Предложение недоступно, если
  после allocation останется меньше `512 MiB` свободного диска; существующий
  достаточный swap не усваивается и не изменяется.
- Managed swap имеет фиксированный путь `/var/lib/vpnctl/swapfile`, mode `0600`
  и отдельный vpnctl-owned systemd unit; `/etc/fstab` не редактируется. Status
  сверяет state record, файл, unit, enablement и active state. `uninstall`
  отключает swap и удаляет unit, сохраняя allocation file и disabled ownership
  record вместе с `/var/lib/vpnctl`; `purge` дополнительно удаляет точный
  managed swap file. Чужой файл/unit/symlink не усваивается и не удаляется.
- Release scope `v2.0` включает все requirements актуального snapshot, кроме
  пунктов, явно перечисленных ниже в разделе «Явно вне scope v2.0». Возможности
  v1 не считаются автоматически готовыми: они должны быть сохранены или
  адаптированы к новой architecture и пройти v2 acceptance tests вместе с
  новыми private-node/transport/ingress capabilities.
- Milestones являются только порядком реализации и risk reduction. Первый
  internal vertical slice может проверять один private node, restricted
  Telegram egress и один HTTPS expose, но это не partial v2 release и не
  переносит остальные non-backlog requirements на будущую версию.
- `v2.0` release gate достигается только после реализации всех non-backlog
  requirements, завершения обязательных technical spikes и прохождения полного
  acceptance/resource/migration test suite. До этого ни один промежуточный
  milestone не называется завершённым v2.0.

### 14. Явно вне scope v2.0

- multi-gateway mesh, gateway failover и geo/load balancing;
- node-to-node networking;
- automatic transport detection/fallback/switching;
- одновременные steady-state active transports и независимый выбор transport
  для control, reverse tunnel и egress; это отдельная backlog growth point;
- назначение routing policy отдельному process, Linux user, systemd unit,
  container или network namespace вместо host-wide routing на private node;
- raw Mihomo rule/config passthrough как advanced escape hatch; v2.0 presets
  используют только безопасную selector schema vpnctl;
- публичный management API и multi-tenant control plane;
- remote laptop controller и Web UI;
- Docker/Kubernetes deployment;
- generic TCP/UDP ingress и произвольное protocol multiplexing на `443/TCP`;
- полноценный IPv6 data plane;
- domain-based public ingress и ACME certificate lifecycle;
- URL/subscription/QR delivery;
- scheduled/remote backups и интеграции с external storage/secret managers;
- portable backup/restore или cloning identity private node;
- invite files;
- размещение пользовательских приложений на gateway.

### 15. Технические решения, ещё требующие spike/design

Product behavior выше зафиксирован. До реализации полного v2 остаётся выбрать
или подтвердить деталями реализации:

1. Restricted transport, фаза B: live E2E prototype на pinned Mihomo и
   фактическом Clash Mi, включая TCP, DNS и UDP-over-TCP; resource benchmark на
   Ubuntu 24.04, 1 vCPU/512 MB; проверка ShadowTLS v3 strict mode и выбор
   handshake host. Статический audit совместимости Mihomo/UoT завершён.
2. Отдельный nginx reverse-proxy process для подтверждённого Telegram IP-only
   flow: live E2E и resource prototype на Ubuntu 24.04, 1 vCPU/512 MB должен
   подтвердить streaming без записи body на диск, body/header/concurrency
   limits, безопасный graceful reload, корректные `404`/`413`/`503`/`504` и
   concrete certificate algorithm/lifetime. Authoritative ingress model должен
   сохранять extension point для будущего domain/ACME и не зависеть от
   nginx-specific primitives. Caddy остаётся fallback, если nginx не проходит
   acceptance gates; Telegram documentation не задаёт maximum certificate
   validity.
3. Reverse tunnel, фаза B: frp prototype с `tcpMux`, dynamic expose reload,
   controller-backed per-node authorization, reconnect и resource benchmark;
   static comparison завершён, rathole отклонён из-за отсутствия требуемого
   stream multiplexing.
4. Точные nftables hooks/priorities, SSH-port detection и preflight diagnostics
   для конфликтующих external rules.
5. Версионирование внутреннего control protocol, cryptographic formats и
   generation reconciliation.
6. Финальная CLI grammar и JSON schemas.
7. End-to-end acceptance tests, benchmarks и milestone decomposition.

Предпочтительные, но ещё не окончательно подтверждённые реализации:

- Mihomo как routing engine;
- Shadowsocks + ShadowTLS v3 как restricted transport;
- nginx как отдельный reverse proxy process, условно до live E2E/resource
  prototype; Caddy как fallback;
- frp как reverse tunnel, условно до prototype/benchmark.

Формальный план реализации находится в OpenSpec change `vpnctl-v2`:

- `proposal.md` фиксирует полный non-backlog scope;
- `specs/*/spec.md` содержит десять проверяемых capability contracts;
- `design.md` фиксирует architecture, provider boundaries, risks и migration;
- `tasks.md` содержит 156 последовательно упорядоченных проверяемых задач.

Этот handoff сохраняет продуктовый контекст и decision log; при реализации
нормативным planning contract является валидированный OpenSpec change. Код в
рамках создания change не изменялся.

---

## Назначение документа

Этот документ фиксирует текущие решения, инсайты и незакрытые вопросы по **vpnctl v2**. Его задача — передать контекст следующему агенту так, чтобы он мог продолжить уточнение требований без повторного обсуждения уже принятых решений и без преждевременного перехода к реализации.

Репозиторий проекта: <https://github.com/grnkvch/vpnctl>

Текущая стадия: **product discovery / формирование требований**.

Следующий ожидаемый результат: после серии уточняющих вопросов подготовить целостную продуктовую и техническую спецификацию v2.

---

## Краткий контекст

Изначально `vpnctl` задумывался как opinionated zero-config утилита для быстрого развертывания собственного VPN на VPS. Новый сценарий существенно шире:

- есть две VPS в разных регионах;
- одна VPS должна выступать публичным gateway;
- другая VPS находится в регионе с ограничениями;
- только трафик к выбранным доменам или сервисам должен идти через gateway;
- остальной исходящий трафик должен идти напрямую;
- может потребоваться маскировка соединения и устойчивость к DPI;
- gateway должен не только выпускать трафик наружу, но и принимать входящий трафик из интернета;
- внутренний сервис на private node должен публиковаться через gateway без необходимости открывать private node наружу;
- reverse proxy, reverse tunnel, TLS, firewall и service management должны устанавливаться и настраиваться самой утилитой.

Ключевой продуктовый вывод:

> **vpnctl v2 — не менеджер WireGuard, а opinionated gateway orchestrator.**

WireGuard, Mihomo, ShadowTLS, reverse proxy, reverse tunnel, firewall, DNS и systemd являются деталями реализации, а не основной пользовательской моделью.

---

## Зафиксированное направление продукта

### Рабочее позиционирование

> **vpnctl превращает одну или несколько VPS в готовый защищенный сетевой gateway: управляет исходящим трафиком, публикует внутренние сервисы и может работать в ограниченных сетях.**

Короткий вариант обещания:

> **Преврати VPS в защищенный gateway одной командой.**

Формулировка пока рабочая и должна быть уточнена после определения главного целевого пользователя и канонического сценария.

### Продуктовая категория

Рабочее название категории:

> **Opinionated gateway orchestrator**

Это означает:

1. Пользователь описывает намерение и желаемый результат, а не вручную комбинирует сетевые технологии.
2. Утилита поставляет проверенную, целостную и безопасную конфигурацию всех необходимых компонентов.
3. Основные сценарии должны работать с минимальным количеством обязательных параметров.
4. Возможность тонкой настройки допустима как escape hatch, но не должна определять основной UX.
5. Продукт отвечает не только за первоначальную установку, но и за диагностику, обновление и поддержание рабочего состояния.

---

## Главная архитектурная идея

### Каноническая двухузловая топология

```text
                         Internet
                            ⇅
                     ┌─────────────┐
                     │ Gateway VPS │
                     │ public edge │
                     └──────┬──────┘
                            ⇅
              persistent protected connection
                            ⇅
                     ┌─────────────┐
                     │ Private node│
                     │ app / bot   │
                     └─────────────┘
```

Gateway выполняет две равноправные функции.

#### Selective egress

```text
Private node
    │
    ├── selected destinations ──► Gateway ──► Internet
    │
    └── everything else ────────────────────► Internet directly
```

#### Managed ingress

```text
Internet
   │
   ▼
Gateway:443
   │
reverse proxy + reverse tunnel
   │
   ▼
Private node:local-port
```

Private node по возможности сам инициирует постоянное соединение к gateway. Это позволяет:

- не открывать private node для входящих соединений;
- работать за NAT или firewall;
- управлять ingress и egress через один gateway;
- использовать контролируемый защищенный канал между узлами.

### Совместимость с одноузловым сценарием

Простой сценарий из v1 должен сохраниться:

```text
Phone / Laptop ──► Gateway VPS ──► Internet
```

Рабочая гипотеза:

- поддерживать и single-node, и two-node topology;
- считать двухузловую модель основной для нового позиционирования;
- не усложнять старый personal VPN flow.

Это еще необходимо подтвердить как продуктовое решение.

---

## Предлагаемая пользовательская модель

### 1. Gateway

Публично доступная VPS, которая может предоставлять:

- egress в интернет;
- ingress из интернета;
- termination публичного TLS;
- reverse proxy;
- reverse tunnel endpoint;
- NAT и forwarding;
- firewall;
- endpoint защищенного транспорта;
- управление подключенными nodes и clients.

### 2. Node

Машина, подключенная к gateway. В первую очередь:

- Linux VPS;
- сервер приложения;
- домашний Linux-сервер;
- позднее, возможно, desktop или router.

Node может:

- отправлять выбранный исходящий трафик через gateway;
- публиковать локальные сервисы через gateway;
- поддерживать постоянное соединение с gateway;
- работать в сети с фильтрацией и DPI.

### 3. Client

Клиентское устройство для personal VPN:

- iOS;
- Android;
- macOS;
- Windows;
- Linux desktop;
- возможно OpenWrt.

Нужно решить, останется ли `client` отдельной сущностью или будет разновидностью `node` с ограниченным набором capabilities.

### 4. Route

Декларативное правило исходящего трафика.

Примеры намерения:

```text
telegram → gateway
openai   → gateway
default  → direct
```

Пользователь должен иметь возможность задавать:

- готовый сервисный ruleset;
- домен;
- domain suffix / wildcard;
- IP или CIDR;
- позже, возможно, geo-ruleset и удаленный ruleset.

### 5. Expose

Декларация публикации локального сервиса через gateway.

Пример:

```text
name: telegram-webhook
local target: 127.0.0.1:3000
public endpoint: https://bot.example.com
```

На основе одной декларации vpnctl должен настроить весь путь:

```text
DNS/domain prerequisite
        ↓
TLS certificate
        ↓
public listener
        ↓
reverse proxy
        ↓
reverse tunnel
        ↓
local service
        ↓
firewall + system services + health checks
```

### 6. Profile

Opinionated набор реализаций и defaults под конкретную среду.

Предварительные профили:

- `standard` — обычная сеть;
- `restricted` — сеть с фильтрацией/DPI;
- `auto` — установка с рекомендуемым профилем и диагностикой.

Не решено, должен ли `auto` только выбрать профиль во время установки или также выполнять runtime fallback.

---

## Принципы продукта

### Intent over implementation

Основной интерфейс должен выражать намерение:

```bash
vpnctl stealth enable
vpnctl route add telegram
vpnctl expose 127.0.0.1:3000
```

Нежелательный основной UX:

```bash
vpnctl install --mihomo --shadowtls --caddy --rathole
```

Конкретные компоненты могут быть доступны через advanced configuration, но не должны быть обязательными знаниями пользователя.

### Zero-config не означает отсутствие конфигурации

Под zero-config здесь понимается:

- безопасные и подходящие defaults;
- автоматический выбор портов, подсетей и локальных адресов;
- автоматическая генерация secrets;
- автоматическая настройка firewall и forwarding;
- автоматическая установка и регистрация systemd services;
- минимальный набор обязательных решений со стороны пользователя;
- отсутствие внешней пошаговой инструкции, которую нужно выполнить вручную.

Для операций, где отсутствует объективно безопасный default, допускаются:

- интерактивный wizard;
- один обязательный высокоуровневый параметр;
- понятное объяснение, какой внешний prerequisite отсутствует.

### Safe by default

Предварительный обязательный security posture:

- deny unsolicited inbound;
- SSH-доступ не должен случайно потеряться;
- management interfaces не публикуются в интернет;
- node/client isolation по умолчанию;
- случайные уникальные credentials;
- root-only доступ к secrets или более безопасный механизм;
- минимально необходимые firewall rules;
- сервисы автоматически перезапускаются после сбоя;
- private node не требует публичного входящего порта;
- конфигурация должна быть валидирована до применения;
- изменение конфигурации не должно оставлять систему в частично примененном состоянии.

Последние два пункта требуют отдельного проектирования транзакционной модели apply/rollback.

### Desired state и идемпотентность

Целевая модель:

```yaml
gateway:
  profile: restricted

routes:
  default: direct
  through_gateway:
    - telegram
    - openai

exposes:
  - name: telegram-webhook
    target: 127.0.0.1:3000
    domain: bot.example.com
```

Команда:

```bash
vpnctl apply
```

Требования:

- повторный `apply` безопасен;
- результат не зависит от количества повторных запусков;
- vpnctl умеет определить drift;
- изменения должны применяться в предсказуемом порядке;
- перед destructive change должна существовать проверка или rollback strategy.

Нужно решить, будет ли YAML-файл основным интерфейсом, дополнением к CLI или внутренним представлением состояния.

### Opinionated core, controlled escape hatches

В v2 не следует строить универсальный конструктор из любых транспортов, proxy engines и reverse tunnels.

Лучший продуктовый путь:

- небольшое число официальных профилей;
- одна поддерживаемая комбинация компонентов для каждого профиля;
- возможность диагностировать систему как единое целое;
- advanced overrides без обещания поддержки произвольных комбинаций.

---

## Основные сценарии v2

### Scenario 1 — Personal VPN

```text
Phone / Laptop → Gateway → Internet
```

Ожидаемый UX:

```bash
vpnctl gateway init
vpnctl client add iphone
```

Результат может включать:

- конфигурационный файл;
- QR-код;
- профиль для поддерживаемого клиента;
- короткую инструкцию подключения.

### Scenario 2 — Selective egress для Linux node

```text
                         selected → Gateway → Internet
Linux node → routing ────┤
                         default  → Direct
```

Ожидаемый UX:

```bash
# На gateway
vpnctl node invite bot-server

# На private node
vpnctl node join <token>

# Затем
vpnctl route add telegram
```

Критический вопрос: где хранится route policy и на каком узле выполняется routing decision.

Рабочая гипотеза: policy централизованно управляется vpnctl, но применяется локально на node через routing engine.

### Scenario 3 — Managed ingress для HTTP/HTTPS

```text
Internet → Gateway → reverse tunnel → Private node service
```

Ожидаемый UX:

```bash
vpnctl expose 127.0.0.1:3000 \
  --name telegram-webhook \
  --domain bot.example.com
```

vpnctl берет на себя:

- tunnel;
- reverse proxy;
- TLS;
- firewall;
- systemd;
- certificate renewal;
- health check.

Первоначально ingress можно ограничить HTTP/HTTPS. Произвольный TCP/UDP ingress следует рассматривать отдельно.

### Scenario 4 — Restricted network

```text
Private node → disguised protected transport → Gateway
```

Пользовательское намерение:

```bash
vpnctl stealth enable
```

или:

```bash
vpnctl gateway init --profile restricted
```

Техническая реализация не должна быть центром UX.

---

## Текущие технические гипотезы

Ни один пункт этого раздела пока не должен считаться окончательным выбором. Это кандидаты, возникшие в обсуждении.

### Routing engine

Кандидат: **Mihomo**.

Причины рассматривать:

- domain-based routing;
- TUN mode;
- поддержка разных outbound transports;
- существующая близость проекта к Clash/Mihomo-style client configs;
- возможность использовать единый policy layer для selective egress.

Альтернатива для сравнения: sing-box.

### Standard transport

Кандидат: **WireGuard**.

Используется там, где не требуется маскировка и протокол не блокируется.

### Restricted transport

Кандидат: **Shadowsocks + ShadowTLS v3**.

Рабочая схема:

```text
Mihomo / routing engine
        ↓
Shadowsocks
        ↓
ShadowTLS v3
        ↓
Gateway
```

Важно сохранить концептуальное разделение:

- routing policy;
- protected proxy transport;
- traffic disguise / DPI resistance.

Необходимо отдельно валидировать совместимость выбранных реализаций клиента и сервера, operational complexity, observability и upgrade path.

### Reverse proxy

Кандидат: **Caddy**.

Причины рассматривать:

- автоматический TLS;
- простой declarative config;
- certificate renewal;
- удобство для opinionated zero-config UX.

Альтернатива: nginx или встроенный proxy layer, если это уменьшит количество компонентов без потери надежности.

### Reverse tunnel

Кандидаты:

- rathole;
- frp;
- другой устойчивый tunnel daemon;
- временно SSH reverse tunnel для MVP, если продуктовые требования позволят.

Выбор не сделан. Нужны критерии:

- reconnect;
- multiplexing;
- authentication;
- per-service access control;
- TCP/HTTP support;
- metrics;
- upgrade stability;
- простота zero-config orchestration;
- возможность транспорта в restricted network.

### Firewall

Кандидат: **nftables**.

Нужно решить, управляет ли vpnctl отдельной таблицей/chain, не вмешиваясь в пользовательские правила, или полностью владеет firewall на поддерживаемой системе.

### Service management

Кандидат: **systemd** и native binaries.

Docker Compose пока не выбран. Для opinionated системной сетевой утилиты native services могут быть предсказуемее, но решение требует сравнения installation, upgrades, isolation и rollback.

### Supported OS

Предварительная рекомендация для v2.0:

- Ubuntu LTS;
- возможно Debian stable.

Не следует обещать поддержку всех Linux-дистрибутивов до появления тестовой матрицы и CI.

---

## Предварительная форма CLI

Это не финальная команда-схема, а демонстрация желаемого уровня абстракции.

### Инициализация gateway

```bash
vpnctl gateway init
vpnctl gateway init --profile restricted
```

### Подключение node

```bash
# На gateway
vpnctl node invite bot-server

# На private node
vpnctl node join <token>
```

Требуется определить:

- срок жизни invite token;
- что содержит token;
- нужен ли out-of-band verification;
- как происходит key rotation;
- можно ли отозвать node;
- какой узел является source of truth.

### Routing

```bash
vpnctl route add telegram
vpnctl route add domain:example.com
vpnctl route add cidr:203.0.113.0/24
vpnctl route list
vpnctl route remove telegram
```

Нужно решить scope команды:

- на конкретном node;
- на группе nodes;
- глобально для gateway;
- на конкретном client profile.

### Expose

```bash
vpnctl expose 127.0.0.1:3000 \
  --name telegram-webhook \
  --domain bot.example.com
```

Возможные будущие варианты:

```bash
vpnctl expose tcp://127.0.0.1:5432
vpnctl expose http://127.0.0.1:8080
```

Но HTTP/HTTPS-first scope предпочтительнее для v2.0.

### Restricted network

```bash
vpnctl stealth enable
vpnctl stealth disable
vpnctl transport test
vpnctl transport switch standard
vpnctl transport switch restricted
```

Нужно решить, должен ли термин `stealth` использоваться в публичном CLI или лучше выбрать нейтральные `profile restricted`, `network restricted` или `transport protected`.

### Operations

```bash
vpnctl status
vpnctl doctor
vpnctl logs
vpnctl apply
vpnctl plan
vpnctl upgrade
```

Желательная семантика:

- `status` показывает текущее состояние;
- `doctor` активно проверяет end-to-end path;
- `plan` показывает предполагаемые изменения;
- `apply` применяет desired state;
- `upgrade` обновляет vpnctl и управляемые компоненты согласованно.

---

## Предварительный scope v2.0

### Включить

1. Single gateway installation.
2. Personal VPN compatibility.
3. Подключение одного или нескольких Linux nodes.
4. Selective egress по сервисным rulesets и доменам.
5. Режим `default direct`, выбранное через gateway.
6. Standard protected transport.
7. Restricted-network profile с маскированным транспортом.
8. HTTP/HTTPS ingress через reverse tunnel.
9. TLS termination на gateway.
10. Firewall orchestration.
11. systemd service orchestration.
12. `status` и `doctor`.
13. Idempotent apply.
14. Revoke/remove для clients, nodes, routes и exposed services.

### Не включать по умолчанию

1. Multi-gateway mesh.
2. Автоматический failover между регионами.
3. Полностью автоматический runtime transport fallback.
4. Web UI.
5. Kubernetes.
6. Поддержку всех Linux-дистрибутивов.
7. Произвольный конструктор transports.
8. Произвольный UDP ingress.
9. Geo-balancing и load balancing между gateways.
10. Multi-tenant SaaS control plane.
11. Публичный management API.

Эти границы пока рабочие и должны быть подтверждены после уточнения приоритетов.

---

## Ключевые продуктовые решения, уже принятые

1. **Направление продукта:** opinionated gateway orchestrator.
2. **Внутренние технологии не являются основной пользовательской моделью.**
3. **Ingress и egress являются first-class capabilities.**
4. **Reverse proxy и reverse tunnel должны настраиваться самим vpnctl.**
5. **Restricted-network / DPI-resistance рассматривается как важный сценарий.**
6. **Domain-based selective routing является обязательным требованием.**
7. **Private node должен по возможности инициировать соединение к gateway.**
8. **Простой personal VPN flow необходимо сохранить.**
9. **Zero-config должен охватывать firewall, TLS, services и diagnostics, а не только генерацию конфигов.**
10. **Следующий этап — уточнение требований, а не немедленная реализация выбранного стека.**

---

## Рабочие гипотезы, которые нельзя считать решениями

1. Mihomo будет основным routing engine.
2. WireGuard будет standard transport.
3. Shadowsocks + ShadowTLS v3 будет restricted transport.
4. Caddy будет reverse proxy и TLS manager.
5. rathole или frp будет reverse tunnel.
6. nftables будет firewall backend.
7. systemd + native binaries будет deployment model.
8. Ubuntu LTS и Debian stable будут первыми поддерживаемыми ОС.
9. YAML desired-state config станет основой управления.
10. Двухузловая topology станет канонической.

Следующий агент должен явно отделять подтвержденные требования от этих технических гипотез.

---

## Главные открытые вопросы

### A. Целевой пользователь и основное обещание

1. Кто основной пользователь v2:
   - разработчик с Telegram-ботом или сервисом в ограниченном регионе;
   - пользователь personal VPN;
   - self-hoster;
   - DevOps-инженер малого проекта;
   - несколько сегментов с одним общим core?
2. Какой сценарий должен демонстрироваться первым в README?
3. Можно ли сформулировать ценность без терминов VPN, proxy и tunnel?
4. Что пользователь ожидает получить через пять минут после первой команды?

### B. Каноническая топология

1. Считать ли two-node topology основной?
2. Может ли gateway одновременно быть application node?
3. Может ли node подключаться к нескольким gateways?
4. Нужны ли несколько private nodes в v2.0?
5. Требуется ли связь node-to-node или только node-to-gateway?
6. Кто является source of truth для desired state?

### C. Installation и bootstrap

1. Как устанавливается vpnctl: curl script, package repository, binary, Homebrew, apt?
2. Требуется ли root?
3. Что делает `gateway init` на чистой машине?
4. Что происходит на машине с существующим firewall, Caddy/nginx, WireGuard или портом 443?
5. Должен ли vpnctl отказываться, импортировать существующую конфигурацию или сосуществовать?
6. Как реализуется secure join без ручного копирования множества secrets?

### D. Routing semantics

1. Основной default: `selected → gateway`, `everything else → direct`?
2. Нужен ли full-tunnel режим в v2.0?
3. Как обрабатываются DNS-запросы и DNS leaks?
4. Как маршрутизируются literal IP destinations, если правило задано доменом?
5. Что делать с QUIC/HTTP3 и UDP-трафиком?
6. Как ведет себя система при недоступности gateway:
   - fail closed;
   - fail direct;
   - настраиваемая политика?
7. Должны ли сервисные rulesets обновляться автоматически?
8. Кто отвечает за корректность готовых rulesets?
9. Нужен ли per-process, per-user, per-container routing или достаточно host-wide policy?

### E. Restricted transport

1. DPI-resistance является обязательной частью v2.0 или optional profile?
2. Как пользователь включает режим: `stealth`, `restricted`, `protected`?
3. Нужен ли автоматический transport detection?
4. Нужен ли runtime fallback?
5. Как выбирается и валидируется handshake host для ShadowTLS?
6. Что происходит, если порт 443 уже занят ingress reverse proxy?
7. Можно ли безопасно и предсказуемо совмещать public HTTPS ingress и disguised transport на одном IP/порту?
8. Какие observability данные допустимы без раскрытия sensitive traffic metadata?
9. Как обновлять transport components без одновременного обрыва management path?

### F. Ingress и domains

1. Домен обязателен или нужен IP-only сценарий?
2. Должен ли vpnctl уметь предоставлять hostname через внешний сервис?
3. Как подтверждается DNS readiness?
4. Нужны ли wildcard certificates?
5. Требуется ли automatic HTTP-to-HTTPS redirect?
6. Должен ли expose поддерживать path-based routing?
7. Нужны ли WebSocket, gRPC, streaming и большие request bodies?
8. Как задаются access policies для опубликованного сервиса?
9. Нужна ли optional authentication перед upstream?
10. Какие публичные порты разрешены?
11. Что происходит при удалении expose: сертификаты, DNS, tunnel credentials, proxy config?

### G. Security model

1. Где хранятся secrets?
2. Как выполняется rotation?
3. Как отзывается скомпрометированный node?
4. Нужна ли взаимная аутентификация всех node-to-gateway соединений?
5. Должен ли каждый exposed service иметь отдельные tunnel credentials?
6. Как vpnctl избегает потери SSH-доступа?
7. Нужен ли rollback timer для firewall/network changes?
8. Какие telemetry и remote calls допустимы? Предварительный default — без telemetry.
9. Нужна ли supply-chain verification скачиваемых binaries?
10. Как пользователь получает audit trail изменений?

### H. Operations и lifecycle

1. Кто обновляет зависимости и когда?
2. Нужны ли pinned versions?
3. Как выполняется backup/restore?
4. Что включает `doctor`?
5. Какие end-to-end probes обязательны?
6. Должен ли vpnctl собирать support bundle?
7. Как обрабатывается partial failure при `apply`?
8. Нужны ли `plan`, `rollback`, `repair`, `adopt`?
9. Как обнаруживается configuration drift?
10. Что является SLO продукта: установка, reconnect, recovery, certificate renewal?

### I. Совместимость с v1

1. Какие команды v1 обязаны продолжить работать?
2. Нужна ли автоматическая миграция existing installation?
3. Сохраняются ли существующие client configs?
4. Можно ли выполнять in-place migration без потери connectivity?
5. Следует ли v1 и v2 использовать разные state directories и systemd units?
6. Нужно ли выпускать отдельную major binary или команда `vpnctl migrate` достаточна?

---

## Приоритетный порядок следующей продуктовой сессии

Следующему агенту рекомендуется не задавать весь опросник сразу. Нужно идти блоками и после каждого блока фиксировать решения.

### Блок 1 — Product contract

Цель: определить, кому и какое главное обещание дает vpnctl v2.

Нужно получить ответы на:

1. Кто основной пользователь?
2. Какой один сценарий является главным?
3. Что обязано произойти после одной команды?
4. Где проходит граница между zero-config и обязательным вводом пользователя?
5. Какой результат считается успешным через первые пять минут?

### Блок 2 — Canonical topology

Цель: определить поддерживаемые роли и источник состояния.

Нужно выбрать:

- single gateway vs gateway + private node;
- один или несколько nodes;
- gateway как dedicated edge или также application host;
- централизованная или локальная конфигурация;
- lifecycle join/revoke/remove.

### Блок 3 — Egress contract

Цель: точно описать поведение selective routing.

Нужно зафиксировать:

- default route policy;
- типы selectors;
- DNS behavior;
- failure behavior;
- UDP/QUIC scope;
- host-wide или granular routing.

### Блок 4 — Ingress contract

Цель: точно описать, что обещает `vpnctl expose`.

Нужно зафиксировать:

- HTTP/HTTPS-only или generic TCP;
- domain requirement;
- TLS ownership;
- reverse tunnel lifecycle;
- health checks;
- access control;
- конфликт портов и существующего reverse proxy.

### Блок 5 — Restricted-network contract

Цель: определить user-facing semantics без преждевременной привязки к ShadowTLS.

Нужно зафиксировать:

- когда пользователь включает restricted profile;
- что гарантирует этот профиль;
- fallback behavior;
- диагностику;
- coexistence с ingress;
- критерии выбора технологии.

### Блок 6 — Operations и migration

Цель: превратить установочный скрипт в управляемый продукт.

Нужно зафиксировать:

- state model;
- idempotency;
- plan/apply/rollback;
- upgrades;
- backups;
- migration from v1;
- supported OS matrix.

---

## Инструкция следующему агенту

Продолжай работу как product/system-design facilitator.

### Обязательные правила сессии

1. Не возвращайся к вопросу, является ли продукт gateway orchestrator: это уже принято.
2. Не начинай с выбора библиотек и демонов.
3. Для каждого обсуждаемого пункта отделяй:
   - user need;
   - product requirement;
   - operational guarantee;
   - implementation hypothesis.
4. Задавай вопросы небольшими тематическими блоками, предпочтительно 3–6 вопросов за раз.
5. После ответов пользователя обновляй decision log.
6. Если пользователь выбирает конкретную технологию, уточняй, является ли это обязательным требованием или текущим предпочтением.
7. Сохраняй opinionated zero-config philosophy: не перекладывай на пользователя ручное соединение компонентов.
8. Проверяй каждый новый feature against scope v2.0.
9. Явно фиксируй default behavior и failure behavior.
10. В конце discovery подготовь спецификацию, пригодную для декомпозиции на milestones и implementation tasks.

### Рекомендуемая первая реплика следующего агента

> Мы уже зафиксировали vpnctl v2 как opinionated gateway orchestrator. Начнем с product contract, потому что он определит все остальные defaults. Нужно выбрать главный first-class сценарий и точное обещание zero-config. Ответь на пять вопросов ниже...

После этого задать вопросы из блока **Product contract**.

---

## Decision log

| Статус | Решение | Комментарий |
|---|---|---|
| Принято | v2 — opinionated gateway orchestrator | Не WireGuard manager |
| Принято | Ingress и egress — first-class | Gateway двунаправленный |
| Принято | Reverse proxy входит в ответственность vpnctl | Не внешняя ручная инструкция |
| Принято | Reverse tunnel входит в ответственность vpnctl | Private node не должен требовать public inbound |
| Принято | Selective routing по доменам обязателен | IP-only routing недостаточен |
| Принято | Restricted-network use case важен | Точная гарантия еще не определена |
| Принято | Технологии должны быть скрыты за intention-oriented UX | Advanced overrides допустимы |
| Принято | Personal VPN flow нужно сохранить | Совместимость и migration не определены |
| Гипотеза | Two-node topology станет канонической | Нужно подтвердить |
| Гипотеза | Mihomo — routing engine | Сравнить с sing-box и требованиями |
| Гипотеза | WireGuard — standard transport | Не должен быть единственным transport |
| Гипотеза | Shadowsocks + ShadowTLS v3 — restricted transport | Требуется техническая валидация |
| Гипотеза | Caddy — reverse proxy/TLS | Не финальный выбор |
| Гипотеза | rathole/frp — reverse tunnel | Не финальный выбор |
| Гипотеза | nftables + systemd + native binaries | Не финальный выбор |
| Открыто | Главный пользователь и first-class scenario | Следующий вопрос discovery |
| Открыто | Domain/TLS zero-config contract | Критично для expose |
| Открыто | Failure semantics routing | Fail-direct vs fail-closed |
| Открыто | Desired-state source of truth | CLI, YAML или hybrid |
| Открыто | Migration path from v1 | Нужен анализ текущей реализации |

---

## Критерии готовности требований

Discovery можно считать завершенным, когда для каждого first-class scenario определены:

1. Пользователь и его исходное состояние.
2. Одна или несколько команд happy path.
3. Все обязательные inputs.
4. Все автоматически выбираемые defaults.
5. Создаваемые системные ресурсы.
6. Security guarantees.
7. Failure behavior.
8. Diagnostics.
9. Remove/rollback behavior.
10. Upgrade behavior.
11. Ограничения и unsupported cases.
12. Acceptance criteria, которые можно автоматизировать в integration tests.

После этого можно переходить к отдельным документам:

- Product Requirements Document;
- System Design;
- CLI specification;
- State/config schema;
- Security model;
- Migration plan;
- v2.0 milestone plan.

---

## Итоговая рамка

vpnctl v2 должен восприниматься не как набор автоматизированных инструкций по установке нескольких сетевых программ, а как единый продукт с понятным контрактом:

```text
User intent
    ↓
vpnctl desired state
    ↓
Orchestration of gateway, node, routes and exposes
    ↓
Transport + routing + TLS + tunnel + firewall + services
    ↓
Observable and recoverable working gateway
```

Главный следующий шаг — определить **product contract**: основной пользователь, главный сценарий и точные границы обещания «zero-config».
