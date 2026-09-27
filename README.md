# 离线 CAA 授权 API

基于 FastAPI 的**离线** CAA（Certificate Authority Authorization，RFC 8659）签发判定服务。
调用方在请求体内自带 DNS 视角（最多 100 条 CAA / CNAME 记录），服务**不发起任何真实 DNS 查询**，
从域名逐级上溯、跟随 CNAME 别名，找到首个生效 CAA 集后给出「允许 / 拒绝签发」结论与完整查找轨迹。
`POST /v1/issuance/route` 可一次提交多个签发请求与多个 CA 的容量，先逐对判定授权，再在容量约束下
完成「最大化分配数 + 字典序最优」的 CA 分配。
`POST /v1/authorize/change-impact` 可提交一批删除 / 新增编辑，审查它们会翻转哪些查询的签发许可，
并为每个翻转给出可重现新版判定的最小编辑子集。
`POST /v1/records/minimize` 则只删不增：在保持所有提交查询的 `authorized` 与 `effective_owner`
不变的前提下，求原记录集的最短子序列。
`POST /v1/authorize/rollout-window` 面向快照灰度切换：对比 before / after 两个记录快照找出
记录多重集发生变化的 owner，在每个变化 owner 的旧值寿命内枚举所有新旧混合快照，求
全部混合组合都与全新快照判定一致的最早整数秒，并报告 t=0 时首个不安全组合。
也可先用 `POST /v1/records/import-zone` 把 BIND zone 文本解析成记录列表，再交给授权接口判定；
反过来，`POST /v1/records/export-zone` 可把记录列表导出为 BIND zone 片段，
且能被 import-zone 原样回读（内容与顺序往返一致）。

## 单条命令启动（Docker）

```bash
docker run -d --name caa-api -p 8080:8080 $(docker build -q .)
```

或使用 Docker Compose（含健康检查与自动重启）：

```bash
docker compose up -d --build
```

- **端口**：`8080`（容器内监听 `0.0.0.0:8080`，可在 `docker-compose.yml` 改映射）
- 健康检查：`GET http://localhost:8080/health`
- 交互式文档：`http://localhost:8080/docs`（Swagger UI）

不用 Docker 时的本地启动方式：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## API

### `POST /v1/authorize`

请求体：

| 字段       | 类型            | 必填 | 说明                                                       |
| ---------- | --------------- | ---- | ---------------------------------------------------------- |
| `domain`   | string          | 是   | 待判定的域名（忽略大小写与单个尾点）                       |
| `wildcard` | boolean         | 否   | 是否申请通配符证书，默认 `false`                           |
| `ca`       | string          | 是   | 签发 CA 的域名（忽略大小写与尾点）                         |
| `records`  | array ≤ 100 条  | 否   | 离线 DNS 记录集，元素为 CAA 或 CNAME 记录                  |

CAA 记录：`{"type":"CAA","owner":"...","flag":0|128,"tag":"issue|issuewild|...","value":"..."}`

CNAME 记录：`{"type":"CNAME","owner":"...","target":"..."}`

响应体：

| 字段              | 说明                                                    |
| ----------------- | ------------------------------------------------------- |
| `authorized`      | 是否允许该 CA 签发                                      |
| `effective_owner` | 首个生效 CAA 集的 owner；全程无 CAA 时为 `null`         |
| `matched_tag`     | 命中的标签（`issue` / `issuewild`），无则 `null`        |
| `matched_value`   | 命中的 value，无则 `null`                               |
| `reason`          | 人读判定理由                                            |
| `trace`           | 逐级 / 逐跳查找轨迹（query、kind、cname 目标、跳数、CAA 集） |

### 判定规则

1. **规范化**：所有域名（domain、ca、owner、target、issue/issuewild 的 value）统一小写、
   去单个尾点；非法名称（空标签、标签超 63 字符、非法字符、以 `-` 开头/结尾、通配符 `*` 等）返回 **422**。
2. **记录校验（422）**：`flag` 仅允许 `0` / `128`；`issue` / `issuewild` 的 `value`
   只接受**裸域名或空串**（不接受 `;parameters`）；同一 owner 混用 CAA 与 CNAME、同一 owner 多条 CNAME 均拒绝；
   记录总数超过 100 拒绝。
3. **查找顺序**：从查询域名开始逐级上溯（`www.example.com → example.com → com`）。
   每到一个名字先跟随其 CNAME 链；跟随别名后从**目标名**继续逐级上溯，
   **不再回到原域名的父级**。沿途**第一个含 CAA 记录的名字即生效集**，其后父级不再考虑。
4. **别名限制（422）**：CNAME 跳数在整个查找过程（含跨父级）中累计，成环（含自指，
   即任何名字被重复访问）或累计超过 **8 跳**返回 422。
5. **未知关键标签**：生效集中存在 `flag=128` 且标签不属于
   `issue / issuewild / iodef / contactemail / contactphone` 的记录时，直接拒绝签发。
6. **通配符选择**：`wildcard=true` 且存在 `issuewild` 时用 `issuewild`，否则回退 `issue`；
   普通域名**只看 `issue`**（`issuewild` 不影响普通证书）。
7. **标签缺失即允许；存在则必须匹配**：生效集中没有适用标签 → 允许；
   存在适用标签时，至少一条**非空 value**（小写去尾点后）与 CA 域名完全相等才允许。
   空串 value 是「显式拒绝所有 CA」，永远不匹配。

### `POST /v1/authorize/patch-plan`

在现有记录集上为「被拒绝的目标查询」寻找**只新增一条 `flag=0` CAA 记录**的补丁方案。

请求体在 `/v1/authorize` 的基础上调整：`records` 最多 **99** 条，并新增 `protected`
（最多 **20** 组，每组含 `domain` / `wildcard` / `ca`），表示判定结果必须保持不变的查询。

| 字段        | 类型           | 必填 | 说明                                             |
| ----------- | -------------- | ---- | ------------------------------------------------ |
| `domain`    | string         | 是   | 目标域名                                         |
| `wildcard`  | boolean        | 否   | 目标是否申请通配符证书，默认 `false`             |
| `ca`        | string         | 是   | 目标签发 CA 的域名                               |
| `records`   | array ≤ 99 条  | 否   | 离线 DNS 记录集（CAA / CNAME）                   |
| `protected` | array ≤ 20 组  | 否   | 需保持 `authorized` 不变的查询（domain/wildcard/ca） |

补丁规则：

1. 先用现有记录对目标与全部 protected 查询各跑一次判定（沿用上述全部校验与别名 422 规则）。
2. 目标已获授权 → 返回 `already_authorized`，不生成补丁。
3. 否则按**目标查找轨迹的经过顺序**逐个尝试候选 owner：仅限轨迹中实际经过且
   **非 CNAME** 的名称（即轨迹里执行了 CAA 查找的节点）；新增记录为
   `flag=0`、普通域名用 `issue`、通配符用 `issuewild`、`value` 为目标 CA。
4. 每试一个候选，就把该记录并入记录集重跑目标与全部 protected：
   **目标须获授权，且所有 protected 的 `authorized` 均不变**，该候选才合格。
5. 取轨迹中最先经过的合格 owner 返回；所有候选都不合格返回 `no_solution`。

响应体：

| 字段                      | 说明                                                          |
| ------------------------- | ------------------------------------------------------------- |
| `status`                  | `patched` / `already_authorized` / `no_solution`              |
| `added_record`            | 需新增的 CAA 记录（type/owner/flag/tag/value），无补丁时 `null` |
| `before_effective_owner`  | 补丁前目标的生效 owner（全程无 CAA 时为 `null`）               |
| `after_effective_owner`   | 补丁后目标的生效 owner；未打补丁时为 `null`                     |
| `reason`                  | 人读判定理由                                                  |

```bash
curl -s -X POST http://localhost:8080/v1/authorize/patch-plan \
  -H 'Content-Type: application/json' \
  -d '{
        "domain": "www.example.com",
        "wildcard": false,
        "ca": "letsencrypt.org",
        "records": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"pki.goog"}
        ],
        "protected": [
          {"domain":"api.example.com","wildcard":false,"ca":"pki.goog"}
        ]
      }'
```

```json
{
  "status": "patched",
  "added_record": {"type":"CAA","owner":"www.example.com","flag":0,"tag":"issue","value":"letsencrypt.org"},
  "before_effective_owner": "example.com",
  "after_effective_owner": "www.example.com",
  "reason": "add issue record for letsencrypt.org at www.example.com; target effective owner changes example.com -> www.example.com"
}
```

### `POST /v1/authorize/change-impact`

审查一批 **CAA / CNAME 变更**对签发许可的影响：在基线记录集上**同时应用全部 edits** 得到新版记录集，
逐个比较各查询在两版上的 `authorized`，只返回发生**翻转**的查询，并为每个翻转找出
**能单独作用于基线并重现新版判定的最小编辑子集**。

请求体：

| 字段      | 类型            | 必填 | 说明                                                                       |
| --------- | --------------- | ---- | -------------------------------------------------------------------------- |
| `records` | array ≤ 100 条  | 否   | 基线离线 DNS 记录集（与 `/v1/authorize` 相同的 CAA / CNAME 记录）          |
| `edits`   | array 1～8 项   | 是   | 变更列表，每项二选一：`{"remove": <下标>}` 或 `{"add": <新记录>}`         |
| `queries` | array 1～20 个  | 是   | 查询列表，每项含**唯一** `id` 与 `domain` / `wildcard` / `ca`              |

编辑规则：

1. **下标语义**：`remove` 的值是指向**基线记录的零基下标**；多个 remove 下标不得重复（422），
   越界（含负）同样 422。下标始终按原基线位置解释，删除不会使后续下标移位。
2. **应用顺序**：先按下标删除基线记录，再把 `add` 的新记录**按编辑顺序追加**到末尾，得到新版记录集。
3. **两版均须合法**：基线与新版记录集都必须通过现有全部记录与别名校验——同一 owner 混用
   CAA / CNAME、同一 owner 多条 CNAME、CNAME 成环、累计超过 8 跳、名称非法、flag 非法等均返回 **422**；
   新版记录总数超过 100 同样返回 422。
4. **逐查询比较**：每个查询分别在基线与新版上执行一次完整 `/v1/authorize` 判定；
   仅 `authorized` 发生翻转的查询进入响应，并按**查询输入顺序**给出前后判定与
   `before_effective_owner` / `after_effective_owner`。
5. **最小编辑子集**：对每个翻转，按子集大小（1 起）递增枚举出 edits 的下标子集，把该子集
   **单独作用于基线**后重跑该查询；第一个使 `authorized` 等于**新版判定**的子集即答案。
   同大小并列时取**编辑序号列表字典序最小**者（序号同样为零基）。
6. **无效子集跳过**：子集应用后记录数超过 100、记录集自身非法（混用 / 多条 CNAME）或判定时
   触发别名错误（成环 / 超 8 跳）的子集一律跳过，不影响其它子集的搜索。

响应体：

| 字段                     | 说明                                                                 |
| ------------------------ | -------------------------------------------------------------------- |
| `flips`                  | 翻转查询列表，按查询输入顺序；无翻转时为 `[]`                        |
| `flips[].id`             | 查询 id                                                              |
| `flips[].before_authorized` / `after_authorized` | 基线 / 新版的授权判定                  |
| `flips[].before_effective_owner` / `after_effective_owner` | 基线 / 新版的生效 CAA owner（无则 `null`） |
| `flips[].minimal_edits`  | 可重现新版判定的最小编辑子集（零基编辑序号，字典序并列取最小）       |

```bash
curl -s -X POST http://localhost:8080/v1/authorize/change-impact \
  -H 'Content-Type: application/json' \
  -d '{
        "records": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"pki.goog"}
        ],
        "edits": [
          {"add": {"type":"CAA","owner":"www.example.com","flag":0,
                   "tag":"issue","value":"letsencrypt.org"}}
        ],
        "queries": [
          {"id":"www-le","domain":"www.example.com","wildcard":false,"ca":"letsencrypt.org"},
          {"id":"www-goog","domain":"www.example.com","wildcard":false,"ca":"pki.goog"},
          {"id":"api-goog","domain":"api.example.com","wildcard":false,"ca":"pki.goog"}
        ]
      }'
```

```json
{
  "flips": [
    {
      "id": "www-le",
      "before_authorized": false,
      "after_authorized": true,
      "before_effective_owner": "example.com",
      "after_effective_owner": "www.example.com",
      "minimal_edits": [0]
    },
    {
      "id": "www-goog",
      "before_authorized": true,
      "after_authorized": false,
      "before_effective_owner": "example.com",
      "after_effective_owner": "www.example.com",
      "minimal_edits": [0]
    }
  ]
}
```

`api-goog` 两版均允许（新版最近生效集在 `www.example.com`，不影响 `api.example.com` 继续命中
父级 `example.com` 的 pki.goog 授权），因此不出现在 `flips` 中。

### `POST /v1/authorize/rollout-window`

快照切换安全窗口：记录集从 `before` 快照切到 `after` 快照期间，缓存可能按 owner 各自
保留旧记录直到其寿命（`stale_seconds`）到期，解析结果因此是**新旧混合**快照。本接口
枚举所有可能的混合组合，求**所有组合都与全新快照判定一致**的最早整数秒。

请求体：

| 字段            | 类型                  | 必填 | 说明                                                            |
| --------------- | --------------------- | ---- | --------------------------------------------------------------- |
| `before`        | array ≤ 100 条        | 否   | 旧快照记录集（CAA / CNAME）                                      |
| `after`         | array ≤ 100 条        | 否   | 新快照记录集（CAA / CNAME）                                      |
| `queries`       | array 1～12 个        | 是   | 查询列表，每项含**唯一** `id` 与 `domain` / `wildcard` / `ca`    |
| `stale_seconds` | object owner→1～86400 | 否   | 各**变化 owner** 的旧值寿命秒数；必须恰好覆盖全部变化 owner      |

窗口规则：

1. **变化 owner**：把两个快照的记录按规范化（owner 小写去尾点、tag 小写、issue/issuewild
   的 value 规范化）后的**记录多重集**逐 owner 比较；多重集不同即变化。只出现在一侧的
   owner 也算变化——缺失一侧按空多重集计，即新增 owner 的旧组为空集、被删 owner 的新组
   为空集。变化 owner 最多 **8** 个，超出返回 422。
2. **寿命映射**：`stale_seconds` 的键（同样规范化，重复键 422）必须与变化 owner 集合
   **恰好一致**，缺失或多余均返回 422；无变化时映射必须为空。
3. **混合快照**：整数秒 `t` 时，寿命未到期（`t < stale_seconds`）的变化 owner 可独立地
   **整组**取旧或取新；已到期的只取新；未变化 owner 固定不变。每个组合拼成一个混合
   记录集，按 `/v1/authorize` 的全部规则逐查询判定。
4. **不安全**：某组合在任一查询上触发别名错误（CNAME 成环 / 超 8 跳），或任一查询的
   `authorized` / `effective_owner` 与**全新快照**不同。
5. **安全秒数**：取旧值集合为 `O` 的不安全组合在 `t < min(stale_seconds[o])`（o ∈ O）
   期间都可能出现，因此 `safe_from` 为所有不安全组合的 `min` 寿命的**最大值**；
   没有不安全组合时（含无变化）为 0。`t` 达到最大寿命后只剩全新快照，必然安全。
6. **t=0 首个不安全组合**：组合按「变化 owner 字典序编号、掩码递增」枚举（位为 1 表示
   该 owner 取旧值；掩码 0 即全新快照，必然安全），报告第一个不安全组合所用旧值 owner
   列表，以及按查询输入顺序首个失败——判定不同给出查询 id，别名错误给出错误类型。

响应体：

| 字段                      | 说明                                                          |
| ------------------------- | ------------------------------------------------------------- |
| `changed_owners`          | 变化 owner 列表（字典序）                                     |
| `safe_from`               | 所有混合组合均安全的最早整数秒；无不安全组合（含无变化）时为 0 |
| `first_unsafe`            | t=0 首个不安全组合；t=0 即安全时为 `null`                     |
| `first_unsafe.old_owners` | 该组合中取旧值的 owner（字典序）                              |
| `first_unsafe.query_id`   | 首个判定不同的查询 id；别名错误时为 `null`                    |
| `first_unsafe.error`      | 别名错误类型（如 `CNAMELoopError`）；判定不同时为 `null`      |

错误（**422**）：`before` / `after` 超过 100 条、查询数量越界或 id 重复 / 空白、寿命值
越界（1～86400）、寿命映射未恰好覆盖变化 owner、变化 owner 超过 8 个，以及在**全旧**或
**全新**快照上判定任一查询时触发名称 / 记录 / 别名错误（混用、多条 CNAME、成环、超 8 跳等）。

```bash
curl -s -X POST http://localhost:8080/v1/authorize/rollout-window \
  -H 'Content-Type: application/json' \
  -d '{
        "before": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"pki.goog"}
        ],
        "after": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"letsencrypt.org"}
        ],
        "queries": [
          {"id":"q-le","domain":"www.example.com","wildcard":false,"ca":"letsencrypt.org"},
          {"id":"q-goog","domain":"www.example.com","wildcard":false,"ca":"pki.goog"}
        ],
        "stale_seconds": {"example.com": 30}
      }'
```

```json
{
  "changed_owners": ["example.com"],
  "safe_from": 30,
  "first_unsafe": {"old_owners": ["example.com"], "query_id": "q-le", "error": null}
}
```

`t < 30` 时 `example.com` 可能仍服务旧值 `pki.goog`，使 `q-le` 被拒（与全新快照的允许
不同）；`t ≥ 30` 后该 owner 只取新值，所有混合组合与全新快照一致，切换安全。

### `POST /v1/issuance/route`

批量签发路由：先按 `/v1/authorize` 的规则判定每个请求的每个候选 CA 能否签发，
再在各 CA 容量约束下为每个请求**至多分配一个**获授权 CA。

请求体：

| 字段       | 类型            | 必填 | 说明                                                         |
| ---------- | --------------- | ---- | ------------------------------------------------------------ |
| `cas`      | array 1～4 个   | 是   | CA 容量列表，每项 `{"ca": "<域名>", "capacity": 0～12}`，CA 唯一 |
| `requests` | array 1～12 个  | 是   | 签发请求列表，每项含 `id` / `domain` / `wildcard` / `candidates` |
| `records`  | array ≤ 100 条  | 否   | 离线 DNS 记录集（与 `/v1/authorize` 相同的 CAA / CNAME 记录）     |

请求项：

| 字段         | 类型            | 说明                                                         |
| ------------ | --------------- | ------------------------------------------------------------ |
| `id`         | string          | 调用方指定的唯一请求 id（非空白）                            |
| `domain`     | string          | 待签发域名（忽略大小写与单个尾点）                           |
| `wildcard`   | boolean         | 是否申请通配符证书，默认 `false`                             |
| `candidates` | array 1～4 个   | **有序**候选 CA 域名：非空、不重复，且每项都必须取自 `cas` 列表 |

路由规则：

1. **先授权后分配**：对每个请求，按 `candidates` 顺序逐个套用 `/v1/authorize`
   的全部判定与 422 规则（名称、记录、CNAME 别名等）；只有 `authorized=true`
   的候选才可被分配。
2. **容量约束**：每个 CA 至多承接其 `capacity` 个请求；每个请求至多分配一个 CA。
3. **优化目标**：首先**最大化已分配请求数**；存在并列时，按请求输入顺序比较
   「所选候选在该请求候选列表中的序号」，**未分配排在所有候选之后**，取整体
   **字典序最小**的方案（即尽量让靠前的请求拿到靠前的候选，只有为了达到最大
   分配数才让位于后续请求）。
4. **未分配原因**：候选中无任何获授权 CA → `"no authorized candidate"`；
   有获授权候选但无法在最优方案中获得容量 →
   `"insufficient capacity for every authorized candidate"`。

响应体：

| 字段       | 说明                                                              |
| ---------- | ----------------------------------------------------------------- |
| `assigned` | 已分配请求总数（最优值）                                          |
| `results`  | 按**请求输入顺序**返回，每项含 `id`、`assigned_ca`（未分配为 `null`）、`reason`（已分配为 `null`） |
| `usage`    | 按 `cas` 输入顺序返回各 CA 的 `ca` / `capacity` / `used` 用量     |

错误（**422**）：沿用 `/v1/authorize` 的名称、记录与别名（成环、超 8 跳、混用、
多条 CNAME）规则；此外 `cas` 中的 CA 重复（规范化后）、请求 `id` 重复、候选为空 /
重复 / 不在 `cas` 列表中、容量越界、数量越界同样返回 422。

容量争用示例（LE 容量仅 1，第二个请求只能用 LE，因此第一个请求被让位给第二候选）：

```bash
curl -s -X POST http://localhost:8080/v1/issuance/route \
  -H 'Content-Type: application/json' \
  -d '{
        "cas": [
          {"ca": "letsencrypt.org", "capacity": 1},
          {"ca": "pki.goog", "capacity": 2}
        ],
        "requests": [
          {"id": "r1", "domain": "a.example.com", "wildcard": false,
           "candidates": ["letsencrypt.org", "pki.goog"]},
          {"id": "r2", "domain": "b.example.com", "wildcard": false,
           "candidates": ["letsencrypt.org"]}
        ],
        "records": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"letsencrypt.org"},
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"pki.goog"}
        ]
      }'
```

```json
{
  "assigned": 2,
  "results": [
    {"id": "r1", "assigned_ca": "pki.goog", "reason": null},
    {"id": "r2", "assigned_ca": "letsencrypt.org", "reason": null}
  ],
  "usage": [
    {"ca": "letsencrypt.org", "capacity": 1, "used": 1},
    {"ca": "pki.goog", "capacity": 2, "used": 1}
  ]
}
```

若某个请求的所有候选都未获授权，其结果为
`{"id": "...", "assigned_ca": null, "reason": "no authorized candidate"}`；
若只是容量不足（含所有获授权 CA 容量为 0），`reason` 为
`"insufficient capacity for every authorized candidate"`。

### `POST /v1/records/import-zone`

把一段 BIND zone 文本解析成**可直接作为 `/v1/authorize` 的 `records` 使用**的 CAA/CNAME
列表（按源顺序排列），每条记录附带它在 zone 文本中的**起始行号**（1 起）。仅做文本解析，
不发起任何 DNS 查询。

请求体：

| 字段     | 类型   | 必填 | 说明                                              |
| -------- | ------ | ---- | ------------------------------------------------- |
| `origin` | string | 是   | 绝对 zone origin（必须以 `.` 结尾）               |
| `zone`   | string | 是   | BIND master-file 文本，不超过 64 KiB（65536 字节） |

支持的 zone 语法（RFC 1035 §5 子集）：

- `$ORIGIN <name>` 切换当前 origin（参数为相对名时按当前 origin 展开）；`$TTL <ttl>` 校验语法；
  `$INCLUDE` / `$GENERATE` 一律拒绝（422），其余未知 `$` 指令按语法错误处理。
- `@` 表示当前 origin；相对 owner / CNAME target 按当前 origin 展开；绝对名以 `.` 结尾。
- 行首空白（空格 / 制表符）表示省略 owner、继承上一条记录的 owner；
  **每条 RR 都会更新被继承的 owner**，包括不导出的类型（A、AAAA、SOA、NS……）。
- 记录中 `TTL`、`IN` 可按任意顺序出现在类型前；CAA / CNAME 之外的类型不导出。
- 括号 `(...)` 允许记录跨行；只有**引号外**的 `;` 开始注释；双引号字符串与反斜杠转义
  （`\X`、`\DDD` 十进制形式）在引号内外均可用。
- CAA rdata 为 `flag tag value` 三项（value 可引号包裹，`""` 表示空串）；CNAME rdata 为单个目标名。
  名称与记录**沿用 `/v1/authorize` 的全部校验规则**（名称合法性、flag 仅 0/128、
  issue/issuewild 的 value 仅裸域名或空串等）。

响应体：

| 字段      | 说明                                                                                     |
| --------- | ---------------------------------------------------------------------------------------- |
| `origin`  | 规范化后的 origin                                                                        |
| `count`   | 导出的记录数                                                                             |
| `records` | 导出的记录，每项含 `line`（起始行号）+ CAA/CNAME 记录字段；该数组可直接作为 `/v1/authorize` 的 `records`（`line` 字段会被忽略） |

错误（均为 **422**，`error_type=ZoneImportError`，响应体含 `line` 源行号）：首条记录就省略
owner（未定义继承 owner）、括号 / 引号不闭合、非法转义、`$INCLUDE` / `$GENERATE`、未知指令、
名称或记录校验失败、导出记录超过 100 条。zone 文本超过 64 KiB、origin 非绝对名同样返回 422。

导入后直接调用授权接口：

```bash
# 1) 导入 zone 文本
curl -s -X POST http://localhost:8080/v1/records/import-zone \
  -H 'Content-Type: application/json' \
  -d '{
        "origin": "example.com.",
        "zone": "$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN CAA 0 issue \"letsencrypt.org\"\nwww 300 IN CNAME edge.cdn.example.\nedge.cdn.example. CAA 0 issue \"letsencrypt.org\""
      }'
```

```json
{
  "origin": "example.com",
  "count": 3,
  "records": [
    {"line": 3, "type": "CAA", "owner": "example.com", "flag": 0, "tag": "issue", "value": "letsencrypt.org"},
    {"line": 4, "type": "CNAME", "owner": "www.example.com", "target": "edge.cdn.example"},
    {"line": 5, "type": "CAA", "owner": "edge.cdn.example", "flag": 0, "tag": "issue", "value": "letsencrypt.org"}
  ]
}
```

```bash
# 2) 用 jq 把导入结果的 .records 直接拼进授权请求
curl -s -X POST http://localhost:8080/v1/records/import-zone \
  -H 'Content-Type: application/json' -d @import.json \
| jq -c '{domain:"www.example.com", wildcard:false, ca:"letsencrypt.org", records:.records}' \
| curl -s -X POST http://localhost:8080/v1/authorize -H 'Content-Type: application/json' -d @-
# authorized=true，effective_owner="edge.cdn.example"（跟随 www 的 CNAME 命中目标上的 CAA）
```

### `POST /v1/records/export-zone`

把 CAA/CNAME 记录列表渲染成 **BIND zone 片段**（与 `/v1/records/import-zone` 互逆）：
导出文本可直接交给 import-zone 回读，回读结果的内容与顺序和**规范化后的输入**完全一致。

请求体：

| 字段          | 类型             | 必填 | 说明                                                   |
| ------------- | ---------------- | ---- | ------------------------------------------------------ |
| `origin`      | string           | 是   | 绝对 zone origin（必须以 `.` 结尾）                    |
| `default_ttl` | integer 1～86400 | 是   | 默认 TTL 秒数，写入 `$TTL` 指令                        |
| `records`     | array ≤ 100 条   | 否   | 待导出的 CAA / CNAME 记录，按此顺序输出                |

导出规则：

1. **沿用记录校验**：记录先经过与 `/v1/authorize` 相同的规范化与同名混用校验——
   同一 owner 混用 CAA 与 CNAME、同一 owner 多条 CNAME 均返回 422。
2. **owner 必须在 zone 内**：每条记录的 owner 须**等于 origin 或位于其子域**，否则 422；
   CNAME 的 target 不受此限（可指向 zone 外）。
3. **文本格式**：首行 `$ORIGIN <origin>.`，次行 `$TTL <default_ttl>`，随后按**输入顺序**
   每条记录一行；owner 等于 origin 时写作 `@`，子域 owner 用相对名（如 `www`），
   CNAME target 用带尾点的绝对名（如 `edge.cdn.example.`）。
4. **CAA value 转义**：value 限 **ASCII**（非 ASCII 返回 422），一律以双引号包裹；
   反斜杠、双引号、分号分别转义为 `\\`、`\"`、`\;`，控制字符（< 0x20 及 0x7F）用
   十进制 `\DDD` 形式（如制表符 `\009`）；空串输出为 `""`。
5. **大小限制**：导出文本超过 64 KiB（65536 字节）返回 422，保证能被 import-zone 回读。

响应体：

| 字段   | 说明               |
| ------ | ------------------ |
| `zone` | BIND zone 片段文本 |

错误（均为 **422**）：origin 非绝对名或名称非法、owner 不在 origin 子域内、同名混用 /
多条 CNAME（沿用记录校验的错误类型）、CAA value 非 ASCII、导出文本超过 64 KiB
（`error_type=ZoneExportError`）；`default_ttl` 越界（1～86400）、记录超过 100 条同样 422。

往返示例（导出 → 回读 → 判定）：

```bash
# 1) 导出 zone 片段
curl -s -X POST http://localhost:8080/v1/records/export-zone \
  -H 'Content-Type: application/json' \
  -d '{
        "origin": "example.com.",
        "default_ttl": 3600,
        "records": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"letsencrypt.org"},
          {"type":"CAA","owner":"example.com","flag":0,"tag":"iodef","value":"mailto:sec@example.com"},
          {"type":"CNAME","owner":"www.example.com","target":"edge.example.com"}
        ]
      }'
```

```json
{
  "zone": "$ORIGIN example.com.\n$TTL 3600\n@ IN CAA 0 issue \"letsencrypt.org\"\n@ IN CAA 0 iodef \"mailto:sec@example.com\"\nwww IN CNAME edge.example.com.\n"
}
```

```bash
# 2) 用 jq 把导出的 .zone 交给 import-zone 回读：内容与顺序不变
curl -s -X POST http://localhost:8080/v1/records/export-zone \
  -H 'Content-Type: application/json' -d @export.json \
| jq -c '{origin:"example.com.", zone:.zone}' \
| curl -s -X POST http://localhost:8080/v1/records/import-zone \
  -H 'Content-Type: application/json' -d @-
```

```json
{
  "origin": "example.com",
  "count": 3,
  "records": [
    {"line": 3, "type": "CAA", "owner": "example.com", "flag": 0, "tag": "issue", "value": "letsencrypt.org"},
    {"line": 4, "type": "CAA", "owner": "example.com", "flag": 0, "tag": "iodef", "value": "mailto:sec@example.com"},
    {"line": 5, "type": "CNAME", "owner": "www.example.com", "target": "edge.example.com"}
  ]
}
```

```bash
# 3) 回读记录可直接交给授权接口
curl -s -X POST http://localhost:8080/v1/records/export-zone \
  -H 'Content-Type: application/json' -d @export.json \
| jq -c '{origin:"example.com.", zone:.zone}' \
| curl -s -X POST http://localhost:8080/v1/records/import-zone \
  -H 'Content-Type: application/json' -d @- \
| jq -c '{domain:"www.example.com", wildcard:false, ca:"letsencrypt.org", records:.records}' \
| curl -s -X POST http://localhost:8080/v1/authorize -H 'Content-Type: application/json' -d @-
# authorized=true，effective_owner="example.com"（跟随 www 的 CNAME 到 edge.example.com，
# 再从其父级上溯命中 @ 上的 issue 记录）
```

### `POST /v1/records/minimize`

记录集精简：**只删除原记录**（不新增、不修改），在保持所有提交查询的判定结果不变的前提下，
求原记录集的**最短子序列**。

请求体：

| 字段      | 类型           | 必填 | 说明                                                              |
| --------- | -------------- | ---- | ----------------------------------------------------------------- |
| `records` | array 1～12 条 | 是   | 待精简的离线 DNS 记录集（与 `/v1/authorize` 相同的 CAA / CNAME 记录） |
| `queries` | array 1～12 个 | 是   | 查询列表，每项含**唯一** `id` 与 `domain` / `wildcard` / `ca`        |

精简规则：

1. **基线**：先按 `/v1/authorize` 的全部规则，用完整记录集求出每个查询的
   `authorized` 与 `effective_owner`；基线判定触发任何名称 / 记录 / 别名错误均返回 **422**。
2. **只删不增**：候选是原记录的子序列（保留下标、保持原顺序），不允许新增或修改记录。
3. **结果不变**：候选须使**每个**查询的 `authorized` 与 `effective_owner` 两项都与基线一致。
4. **错误跳过**：候选子集在判定中触发记录或别名错误（同名混用、多条 CNAME、成环、
   超过 8 跳）时直接跳过，不影响其它候选的搜索。
5. **最短优先**：按保留条数递增枚举候选；同长度并列时取**保留的原下标列表字典序最小**者。
   完整记录集必然与基线一致，因此答案一定存在。

响应体：

| 字段                          | 说明                                       |
| ----------------------------- | ------------------------------------------ |
| `kept`                        | 保留记录的原下标（零基，升序）             |
| `removed`                     | 删除记录的原下标（零基，升序）             |
| `records`                     | 精简后的记录列表，按原顺序排列             |
| `queries`                     | 各查询的基线结果，按查询输入顺序           |
| `queries[].id`                | 查询 id                                    |
| `queries[].authorized`        | 基线授权判定                               |
| `queries[].effective_owner`   | 基线生效 CAA owner（全程无 CAA 为 `null`） |

> **注意**：精简结论**只覆盖本次提交的查询**。未提交的 domain / wildcard / CA 组合在精简后的
> 记录集上可能得到不同判定；需要保护更多查询时，请把它们一并放入 `queries`。

错误（**422**）：`records` / `queries` 数量越界、查询 `id` 重复或空白、名称或记录非法、
基线判定触发记录 / 别名错误等。

```bash
curl -s -X POST http://localhost:8080/v1/records/minimize \
  -H 'Content-Type: application/json' \
  -d '{
        "records": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"letsencrypt.org"},
          {"type":"CAA","owner":"other.net","flag":0,"tag":"issue","value":"pki.goog"}
        ],
        "queries": [
          {"id":"www-le","domain":"www.example.com","wildcard":false,"ca":"letsencrypt.org"}
        ]
      }'
```

```json
{
  "kept": [0],
  "removed": [1],
  "records": [
    {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"letsencrypt.org"}
  ],
  "queries": [
    {"id":"www-le","authorized":true,"effective_owner":"example.com"}
  ]
}
```

`other.net` 的记录不被该查询的查找轨迹触及，删除后判定不变，因此被精简掉。

## 引擎调用边界（准备 / 判定分离）

`app/engine.py` 把「记录准备」与「查询判定」拆成两个独立阶段，供一次操作中的多个查询
复用同一份记录校验结果：

- `prepare_records(records) -> PreparedRecords`：**准备阶段**。一次完成全部记录集级校验——
  owner / target 名称规范化、同一 owner 混用 CAA 与 CNAME、同一 owner 多条 CNAME——
  并生成**脱离输入的不可变索引**（`PreparedRecords` 快照）。之后修改原始 `records`，
  或修改任何一次判定返回的 `trace`，都不会影响该快照及后续判定。
- `evaluate_prepared(domain, wildcard, ca, snapshot) -> dict`：**查询判定**。在已准备的
  快照上执行一次完整查找，返回与 `evaluate` 完全一致的判定、轨迹与错误语义。
  CNAME 成环与累计跳数（>8）属于单次查询沿途经过的性质，仍在查找实际经过时检查（422），
  不属于准备阶段。
- `evaluate(domain, wildcard, ca, records)`：单发兼容包装，相当于
  `evaluate_prepared(domain, wildcard, ca, prepare_records(records))`，
  供 `/v1/authorize` 等单查询入口使用。

批量操作（`/v1/issuance/route` 容量分配、`/v1/authorize/patch-plan` 补丁规划、
`/v1/authorize/change-impact` 变更影响、`/v1/records/minimize` 记录精简、
`/v1/authorize/rollout-window` 灰度窗口）在单次操作内对每个基线、新版或候选记录组
**只准备一次**，该组的全部查询复用同一快照；搜索过程中再次访问内容相同的记录组
（完整编辑子集、全量子序列、全旧 / 全新混合快照等）也直接复用已准备的快照，
准备失败同样记忆、不会重复校验。搜索过程中的无效候选
（同名混用、多条 CNAME、成环、超 8 跳、超 100 条）仍按原规则跳过；
CNAME 成环与跳数检查仍随每个查询实际经过的路径执行，错误先后顺序、
最优解并列顺序与响应结果均不变。

## 示例

### 1) 父级 CAA 授权指定 CA

```bash
curl -s -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{
        "domain": "www.example.com",
        "wildcard": false,
        "ca": "letsencrypt.org",
        "records": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"letsencrypt.org"}
        ]
      }'
```

```json
{
  "authorized": true,
  "effective_owner": "example.com",
  "matched_tag": "issue",
  "matched_value": "letsencrypt.org",
  "reason": "issue property at example.com authorizes CA letsencrypt.org",
  "trace": [
    {"query": "www.example.com", "kind": "caa", "cname_target": null, "cname_hops": 0, "caa": null},
    {"query": "example.com", "kind": "caa", "cname_target": null, "cname_hops": 0,
     "caa": [{"flag": 0, "tag": "issue", "value": "letsencrypt.org"}]}
  ]
}
```

### 2) 通配符：issuewild 优先于 issue

```bash
curl -s -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{
        "domain": "example.com",
        "wildcard": true,
        "ca": "letsencrypt.org",
        "records": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":"letsencrypt.org"},
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issuewild","value":"pki.goog"}
        ]
      }'
# authorized=false，matched_tag="issuewild"（普通证书场景下则为 true，只用 issue）
```

### 3) 跟随 CNAME 别名重查

```bash
curl -s -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{
        "domain": "www.example.com",
        "wildcard": false,
        "ca": "letsencrypt.org",
        "records": [
          {"type":"CNAME","owner":"www.example.com","target":"edge.cdn.example"},
          {"type":"CAA","owner":"edge.cdn.example","flag":0,"tag":"issue","value":"letsencrypt.org"}
        ]
      }'
# effective_owner="edge.cdn.example"，trace 中先记录 cname 跳转再记录 caa 命中
```

### 4) 空串 value 显式拒绝所有 CA

```bash
curl -s -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{
        "domain": "example.com",
        "ca": "letsencrypt.org",
        "records": [
          {"type":"CAA","owner":"example.com","flag":0,"tag":"issue","value":""}
        ]
      }'
# authorized=false
```

### 5) 错误请求（HTTP 422）

```bash
# flag 非法
curl -i -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{"domain":"a.com","ca":"ca.net","records":[{"type":"CAA","owner":"a.com","flag":1,"tag":"issue","value":"ca.net"}]}'
# HTTP/1.1 422 ...
```

CNAME 成环 / 超 8 跳 / 同名混用 / 多条 CNAME 同样返回 422，响应体含 `error_type`
（如 `CNAMELoopError`、`CNAMELimitError`、`MixedRecordsError`、`MultipleCNAMEError`）。

## 项目结构

```
app/
  __init__.py
  engine.py     # 记录准备（prepare_records → 不可变索引）与查询判定（evaluate_prepared）分离；
              # 规范化、逐级上溯、CNAME 链、判定规则（纯逻辑，无 I/O）
  zonefile.py   # BIND zone 文本解析与导出（$ORIGIN/$TTL、owner 继承、括号/引号/转义）
  schemas.py    # Pydantic v2 请求/响应模型与输入校验
  main.py       # FastAPI 路由与 422 异常映射
tests/
  test_api.py             # 48 条 authorize / patch-plan 端到端用例
  test_change_impact.py   # 28 条变更影响审查（change-impact）用例
  test_export_zone.py     # 26 条 zone 导出（export-zone）用例
  test_issuance_route.py  # 24 条批量签发路由用例（pytest + TestClient）
  test_import_zone.py     # 45 条 zone 导入用例
  test_minimize.py        # 26 条记录集精简（minimize）用例
  test_prepare_reuse.py   # 7 条批量搜索记录组只准备一次的回归用例
  test_rollout_window.py  # 26 条快照切换安全窗口（rollout-window）用例
Dockerfile
docker-compose.yml
requirements.txt
```

## 测试

```bash
pip install -r requirements.txt pytest httpx
pytest -q
```
