/**
 * PwnCraft Heap Workbench (v0.32) — the refactored 堆演示.
 *
 * Every demo model (16 templates, or the user's own EXP replay) runs through
 * the real glibc allocator simulation in Python (PhysicalMemory is the truth;
 * tcache/fastbin/unsorted/largebin moves, boundary tags, safe-linking are all
 * emergent from bytes).  The renderer draws a DETERMINISTIC layout: chunk
 * cards stack in address order, bin chains render from snapshot.bins, and
 * chunk geometry only moves through allocator transactions (cell correction,
 * row insert, edge resize).  Every state change — edit, structural edit, EXP
 * replay, live op, reprofile — is committed atomically through
 * commitSnapshot(); the canvas never splices a suffix into a stale package.
 *
 * glibc 版本的单一真值在后端 AllocatorProfile：前端只提交 profile_id 请求，
 * 提交后只相信快照回传的 effective_version / profile_id（Truth Sync）。
 */
(() => {
  'use strict';

  const state = {
    ready: false,
    templates: [],
    heapState: null,          // full bridge heap state
    steps: [],
    current: 0,
    mappings: [],             // helper 别名映射（addchunk → add）
    ops: [],                  // editable operation list
    allocator: null,          // allocator overrides dict
    scenarioName: '',
    learnedRules: [],
    corrections: [],
    episodes: [],
    reviews: [],                  // Agent review 标签层（独立于 Snapshot）
    recognitionCorrections: [],   // 候选标注（RecognitionCorrection）
    snapshotId: '',           // 由后端 state() 签发的整包 id
    memoryRevision: '',       // steps:corrections:rules:edits:operations
    editMode: false,          // 编辑模式（右上角按钮）：只有开启时 + 手柄与拖动才可用
    selectedPhysicalId: null, // 画布选中实体（physical_id 稳定 key）
    selectedCell: null,       // 单元格选中态 { bodyKey, off, half }（编辑模式，纯前端高亮）
    hoveredRowInsert: null,   // 行右下角 ⊕ hover：`${chunkKey}:${rowKey}`
    hoveredResize: null,      // 顶/底边圆形 handle hover：`${chunkKey}:${edge}`
    resizePreview: null,      // 拖动边界时的侵入预览 { y0, y1, kind: 'overlap'|'shrink' }
    structuralPending: false,
    canvasLayout: new Map(),  // LEGACY-ONLY：整块布局拖动已删除，此表不再有任何
                              // 写入方；仅为旧场景文件的 visual_y 保留读取兼容。
                              // 训练截图路径不得依赖它（新会话恒为空 Map）。
    guides: null,             // 拖动时的吸附辅助线（世界坐标 y 数组）
    tab: 'canvas',            // canvas | iofile
    iofile: { symbol: 'stdout', layout: null, bySymbol: {} },   // 版本跟随 TargetContext profile
    camera: { x: 0, y: 0, scale: 1 },
  };

  // 确定性布局容器：不再跑物理步进。bodies 只是可命中测试的矩形数据，
  // 位置由 applyStepToWorld / 拖动直接写入，重绘只在 needsDraw 时发生。
  const world = {
    bodies: [],
    addBody(spec) {
      const body = {
        x: 0, y: 0, w: 60, h: 40, mass: 1,
        pinned: false, noCollide: true, dragging: false,
        data: null, ...spec,
      };
      this.bodies.push(body);
      invalidateHeapBounds();
      return body;
    },
    removeBody(body) {
      this.bodies = this.bodies.filter((item) => item !== body);
      invalidateHeapBounds();
    },
    clear() {
      this.bodies = [];
      invalidateHeapBounds();
    },
  };
  const bodiesByChunk = new Map();   // bodyKey -> body
  let canvas = null;
  let ctx = null;
  let canvasHost = null;
  let binsCanvas = null;             // bins 独立右栏画布（不与 chunk 画布共用一张大图）
  let binsCtx = null;
  let binsHost = null;
  let binsDpr = 1;
  let binsCssW = 300;
  let binsCssH = 300;
  let binsCamera = { y: 0 };         // bins 面板自己的纵向滚动
  let binsNeedsDraw = true;
  let drag = null;                   // layout-drag state (edit mode only)
  let needsDraw = true;
  let localSnapshotSeq = 0;
  let pendingWheelDelta = 0;         // wheel 合帧：事件只累计 delta，tick 每帧消费一次
  const heapBoundsCache = { top: 0, bottom: 0, valid: false };
  // buildChunkGrid 几何模型缓存：step 由 commitSnapshot 整包替换成新对象，
  // WeakMap 随之自动失效，缓存绝不可能跨 snapshot/step 复用。
  const chunkGridCache = new WeakMap(); // step -> Map(chunk -> grid)

  const COLORS = {
    bg: '#141416',
    lane: '#1b1b1e',
    card: '#232327',
    cardBorder: '#3d3d44',
    text: '#c8cad0',
    dim: '#8a8d95',
    allocated: '#4f8cc9',
    freed: '#d78c45',
    stale: '#6e6e6e',
    fake: '#b07fd8',
    reused: '#4faf8f',
    top: '#54545c',
    crossWrite: '#e5554f',    // cross_write：当前字节 provenance 被其他 writer 覆盖
    overlap: '#e5554f',       // physical_overlap：真实物理覆盖，按字节标红（反向斜线区别 cross_write 正斜线）
    tcache: '#3aa0a0',
    fastbin: '#d0a23a',
    unsorted: '#a03a8c',
    smallbins: '#7f9f4a',
    largebins: '#9a6ad0',
  };

  const $ = (sel) => document.querySelector(sel);
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const esc = (value) => String(value ?? '').replace(/[&<>"]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
  }[c]));
  const icon = (name) => window.lucideIcon ? window.lucideIcon(name) : '';

  // =====================================================================
  // Page skeleton

  function render() {
    const host = $('#page-heap');
    host.innerHTML = `
      <div class="heap-toolbar">
        <select id="heap-template" class="input" title="选择演示模板（全部走真实 allocator 仿真）"></select>
        <button id="heap-load-template" class="btn">加载模板</button>
        <span class="toolbar-sep"></span>
        <label class="inline-label">glibc
          <select id="heap-glibc" class="input" title="目标 glibc 版本。切换 = Reprofile 事务：整题重识别重放 + 复验人工 corrections（机制差异全部由后端 AllocatorProfile 决定）">
            ${['2.23', '2.27', '2.29', '2.31', '2.32', '2.33', '2.34', '2.35', '2.36', '2.37', '2.38', '2.39', '2.40']
    .map((v) => `<option value="${v}"${v === '2.35' ? ' selected' : ''}>${v}</option>`).join('')}
          </select>
        </label>
        <span id="heap-glibc-active" class="heap-profile-chip hint-dim" title="加载场景后显示后端实际生效的 allocator profile">ACTIVE: —</span>
        <button id="heap-replay-exp" class="btn" title="把当前 exp.py 源码交给识别器 → 真实回放">回放 EXP</button>
        <span class="flex-spacer"></span>
        <span id="heap-edit-status" class="heap-edit-status" hidden></span>
        <button id="heap-iofile" class="btn" title="以 Typed View 打开 IO FILE（_IO_FILE_plus 字段表）">IO FILE</button>
        <button id="heap-edit" class="btn" title="开启后才能改画布：点单元格选中并校正真实值、行右下角 ⊕ 插入真实物理行、chunk 顶/底边中央 ● 拖动改变物理边界（侵入相邻 chunk 即真实 overlap），全部经 Python 事务校验">编辑模式</button>
        <button id="heap-save-scene" class="btn">保存场景</button>
        <button id="heap-open-scene" class="btn">打开场景</button>
      </div>
      <div class="heap-body">
        <div class="heap-left">
          <div class="heap-exp-head">
            <span class="heap-exp-title">EXP 源代码</span>
            <span class="hint-dim">常驻 · 与 EXP 页/调试页同一编辑器（Semantic Round Trip）</span>
          </div>
          <div id="heap-exp-source-slot" class="heap-exp-source-slot"></div>
          <div id="heap-left-ops" class="heap-left-page">
            <div id="heap-live-ops"></div>
            <div id="heap-canonical"></div>
            <div id="heap-recognition"></div>
            <div id="heap-locate"></div>
            <div id="heap-learn-summary"></div>
          </div>
          <div id="heap-pending" class="heap-pending" hidden></div>
        </div>
        <div class="heap-right">
          <div id="heap-canvas-row" class="heap-canvas-row">
            <div id="heap-canvas-wrap" class="heap-right-page">
              <canvas id="heap-canvas"></canvas>
              <span id="heap-origin-badge" class="origin-badge heap-origin-chip">EMPTY</span>
            </div>
            <div id="heap-bins-wrap" class="heap-bins-wrap">
              <div class="heap-bins-head">bins · 当前状态</div>
              <div id="heap-bins-canvas-host">
                <canvas id="heap-bins-canvas"></canvas>
              </div>
            </div>
          </div>
          <div id="heap-iofile-page" class="heap-right-page" hidden></div>
        </div>
      </div>`;

    canvas = $('#heap-canvas');
    ctx = canvas.getContext('2d');
    canvasHost = $('#heap-canvas-wrap');
    binsCanvas = $('#heap-bins-canvas');
    binsCtx = binsCanvas.getContext('2d');
    binsHost = $('#heap-bins-canvas-host');
    bindToolbar();
    bindCanvas();   // 画布交互（滚轮/拖动/+/双击校正）只在 DOM 创建后绑定一次
    document.querySelector('#page-heap').addEventListener('click', (event) => {
      const tab = event.target.closest('.live-op-tab');
      if (!tab) return;
      state.liveOpKind = tab.dataset.kind;
      renderLiveOps();
    });
    new ResizeObserver(resizeCanvas).observe(canvasHost);
    new ResizeObserver(resizeBinsCanvas).observe(binsHost);
    resizeCanvas();
    resizeBinsCanvas();
    requestAnimationFrame(tick);
    state.ready = true;
  }

  // =====================================================================
  // Allocator profile（TargetContext 单一真值在后端，前端只提交请求）
  //
  // 前端不再计算 safe_linking / tcache 等任何机制位 —— 那是双重真值。
  // 这里只构造「请求」：profile_id + arch + 模式。快照回来之后 UI 只相信
  // effective_version / profile_id（Truth Sync：下拉框与 ACTIVE chip 都以
  // 它为准，请求被后端钳制时显示 ⚠）。

  function glibcSelect() {
    return $('#heap-glibc');
  }

  function selectedGlibcVersion() {
    const select = glibcSelect();
    return select && select.value ? select.value : '2.35';
  }

  function buildAllocatorRequest() {
    const version = selectedGlibcVersion();
    const arch = (window.PwnApp && window.PwnApp.arch) || 'amd64';
    const request = {
      profile_id: `glibc-${version}-${arch}`,
      requested_version: version,
      arch,
      simulation_mode: 'strict',   // 只保留最真实的严格模式：allocator 终止/校验不造假
    };
    const heapBase = state.allocator && state.allocator.heap_base;
    if (heapBase) request.heap_base = heapBase;
    return request;
  }

  /** Truth Sync：下拉框与 ACTIVE chip 只相信后端回传的生效 profile。 */
  function syncGlibcSelector(allocator) {
    const select = glibcSelect();
    if (!select || !allocator) return;
    const effective = String(allocator.effective_version || allocator.version || '').trim();
    if (effective && [...select.options].some((option) => option.value === effective)) {
      select.value = effective;
    }
    const chip = $('#heap-glibc-active');
    if (!chip) return;
    const profileId = String(allocator.profile_id || '');
    const requested = String(allocator.requested_version || '').trim();
    const clamped = Boolean(allocator.clamp_note) || Boolean(requested && effective && requested !== effective);
    chip.textContent = profileId ? `ACTIVE: ${profileId}${clamped ? ' ⚠' : ' ✓'}` : 'ACTIVE: —';
    chip.classList.toggle('heap-profile-warn', clamped);
    chip.title = profileId
      ? `${profileId} · revision ${allocator.profile_revision || '?'}`
        + (clamped ? `\n请求 ${requested} → 生效 ${effective}${allocator.clamp_note ? `\n${allocator.clamp_note}` : ''}` : '')
      : '加载场景后显示后端实际生效的 allocator profile';
  }

  /**
   * 版本切换 = Reprofile 事务：AllocatorProfile 切换 → 原场景整题重新
   * 识别/回放 → 人工 corrections 重新验证 → 全新 Snapshot → Canvas/Bins/
   * Inspector 全刷新（commitSnapshot）。绝不只改 state.allocator 了事。
   */
  async function applyAllocatorProfile() {
    const request = buildAllocatorRequest();
    try {
      const heapState = await window.pwnbao.request('heap_reprofile', { allocator: request });
      // 新 profile 已随整包提交，回放缓存键同步推进，避免紧接的 autoReplay 重复重算。
      lastReplayKey = replayCacheKey((window.PwnApp && window.PwnApp.getExpText()) || '');
      lastFailedKey = null;
      state.iofile.bySymbol = {};   // IO FILE 与 Heap 共用同一 profile，旧观测缓存作废
      absorbState(heapState, 'REPROFILE', false, { resetLayout: true });
      const info = heapState.reprofile || {};
      const invalidated = (info.corrections_invalidated || []).length;
      log(`Reprofile 完成：${info.requested_version || request.requested_version} → `
        + `${info.profile_id || (state.allocator || {}).profile_id} · `
        + `${info.replayed_steps ?? state.steps.length} 步重算 · corrections 保留 ${info.corrections_kept ?? 0}`
        + (invalidated ? `，失效 ${invalidated}` : ''));
      if (info.clamp_note) log(`⚠ ${info.clamp_note}`, 'warn');
    } catch (error) {
      // 事务已回滚：UI 必须回显真正生效的 profile，而不是停留在没生效的选择上。
      syncGlibcSelector(state.allocator || {});
      log(`Reprofile 失败（已回滚到原 profile）：${error.message}`, 'error');
    }
  }

  async function changeGlibcProfile(versionText) {
    const select = glibcSelect();
    if (select && versionText) select.value = versionText;
    if (!state.heapState) {
      log(`glibc 目标已设为 ${selectedGlibcVersion()}：加载场景 / 回放 EXP 时生效。`);
      return true;   // 无活动场景：只是记录请求，没有可回滚的事务
    }
    await applyAllocatorProfile();
    return Boolean(state.allocator && state.allocator.profile_id
      && state.allocator.profile_id === buildAllocatorRequest().profile_id);
  }

  function bindToolbar() {
    $('#heap-load-template').addEventListener('click', async () => {
      const templateId = $('#heap-template').value;
      await loadTemplate(templateId);
    });
    $('#heap-glibc').addEventListener('change', (event) => { changeGlibcProfile(event.target.value); });
    $('#heap-replay-exp').addEventListener('click', replayExp);
    $('#heap-edit').addEventListener('click', () => {
      state.editMode = !state.editMode;
      const button = $('#heap-edit');
      button.classList.toggle('primary', state.editMode);
      button.textContent = state.editMode ? '完成编辑' : '编辑模式';
      log(state.editMode
        ? '编辑模式：点单元格选中、再点同一格编辑真实值；行右下角 ⊕ 在该行下方插入真实物理行（弹窗确认）；拖 chunk 顶/底边中央 ● 改变物理边界（侵入相邻 chunk 即真实 overlap），全部经 Python 事务校验。'
        : '编辑模式已关闭：单元格/插行/边界拖动均不可用。');
      // 退出编辑模式清掉临时选中态，避免残留高亮
      state.selectedCell = null;
      state.hoveredRowInsert = null;
      state.hoveredResize = null;
      state.resizePreview = null;
      if (state.draftRow) closeDraftRow();
      // 编辑模式 = 全量物理行（渲染虚拟化）：卡高随模式变化，重建 world
      world.clear();
      bodiesByChunk.clear();
      invalidateHeapBounds();
      rebuildWorld();
      needsDraw = true;
    });
    $('#heap-iofile').addEventListener('click', () => {
      switchTab(state.tab === 'iofile' ? 'canvas' : 'iofile');
    });
    $('#heap-save-scene').addEventListener('click', saveScene);
    $('#heap-open-scene').addEventListener('click', openScene);
  }

  // =====================================================================
  // Data loading

  async function loadTemplates() {
    const result = await window.pwnbao.request('heap_templates');
    state.templates = result.templates || [];
    const select = $('#heap-template');
    if (!select) return;
    select.innerHTML = '';
    const groups = new Map();
    for (const template of state.templates) {
      if (!groups.has(template.category)) groups.set(template.category, []);
      groups.get(template.category).push(template);
    }
    for (const [category, items] of groups) {
      const group = el('optgroup');
      group.label = category;
      for (const template of items) {
        const option = el('option', '', `${template.title}（${template.operation_count} 步）`);
        option.value = template.template_id;
        group.appendChild(option);
      }
      select.appendChild(group);
    }
  }

  async function loadTemplate(templateId) {
    try {
      // 只提交 profile 请求；机制位（safe_linking/tcache/检查规则）属于后端。
      state.allocator = buildAllocatorRequest();
      state.scenarioName = '';
      const heapState = await window.pwnbao.request('heap_load', {
        template_id: templateId,
        allocator: state.allocator,
      });
      const select = $('#heap-template');
      if (select) select.value = templateId;   // 下拉框与实际场景保持一致
      absorbState(heapState, `模板 ${templateId}`, false, { resetLayout: true });
      switchTab('canvas');
    } catch (error) {
      log(`堆模板加载失败：${error.message}`, 'error');
    }
  }

  // 偏移显示：未指定 heap base 时不发明具体地址，一律 +0x（相对堆起点）。
  // 只有 EXP/场景明确给出 heap_base 时，才允许把绝对地址折算为相对偏移。
  // parseBig 全程 BigInt：0xffffffffffffffff 这类 pwn 常见值不能被 Number 精度吞掉。
  function parseBig(text) {
    const source = String(text ?? '').trim();
    if (!source) return null;
    let sign = 1n;
    let body = source;
    if (body.startsWith('+')) body = body.slice(1);
    else if (body.startsWith('-')) { sign = -1n; body = body.slice(1); }
    if (!/^(?:0x[0-9a-f]+|\d+)$/i.test(body)) return null;
    try {
      return sign * BigInt(body);
    } catch (_) {
      return null;
    }
  }

  function parseAddr(text) {
    const value = parseBig(text);
    if (value === null) return null;
    const limit = BigInt(Number.MAX_SAFE_INTEGER);
    if (value > limit || value < -limit) return null;
    return Number(value);
  }

  function archWord() {
    return ((state.allocator && state.allocator.bits) || 64) >= 64 ? 8 : 4;
  }

  /**
   * 尺寸三拆 —— 「修改 size 字段」与「+ 扩展物理 chunk」永远不再混淆：
   *   physical_extent_size  chunk 实际占据的物理范围（布局/行数唯一依据）
   *   header_raw_size       内存里 size 字段当前的原始值（含 flags，保真）
   *   decoded_chunksize     raw & ~flags（展示/对比用）
   * 三个字段由后端 PhysicalMemory 独立签发，前端只消费，不再从 header size
   * 猜测物理范围；只有换算画布像素时才把 extent 收成 Number（钳制 + 截断）。
   */
  const SIZE_FLAG_MASK = 0x7n;   // PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
  const EXTENT_PIXEL_CLAMP = 0x40000;
  function clampExtent(big) {
    if (big === null || big === undefined || big <= 0n) return null;
    return big <= BigInt(EXTENT_PIXEL_CLAMP) ? Number(big) : EXTENT_PIXEL_CLAMP;
  }
  function chunkSizeTriple(chunk) {
    if (chunk && (chunk.physical_extent_size !== undefined
      || chunk.header_raw_size !== undefined || chunk.decoded_chunksize !== undefined)) {
      const extentBig = parseBig(chunk.physical_extent_size);
      return {
        headerRawSize: chunk.header_raw_size || '',
        decodedChunkSize: parseBig(chunk.decoded_chunksize),
        physicalExtentSize: clampExtent(extentBig),
        physicalExtentBig: extentBig !== null && extentBig > 0n ? extentBig : null,
      };
    }
    // legacy 兜底：没有三拆字段的旧 artifact 只能退回历史近似，
    // 不再声称那是当前真实物理 extent。
    const legacyRaw = chunk && (chunk.original_chunk_size ?? chunk.chunk_size ?? chunk.size);
    const legacyBig = parseBig(legacyRaw);
    const legacyDecoded = legacyBig === null ? null : (legacyBig & ~SIZE_FLAG_MASK);
    return {
      headerRawSize: legacyRaw ?? '',
      decodedChunkSize: legacyDecoded,
      physicalExtentSize: clampExtent(legacyDecoded),
      physicalExtentBig: legacyDecoded !== null && legacyDecoded > 0n ? legacyDecoded : null,
    };
  }

  function chunkSizeValue(chunk) {
    const triple = chunkSizeTriple(chunk);
    return triple.physicalExtentSize;
  }

  function explicitHeapBaseValue() {
    if (!state.heapState || !state.heapState.heap_base_specified) return null;
    const vars = state.heapState.variables || {};
    const step = state.steps[state.current] || {};
    const allocator = state.heapState.allocator || state.allocator || {};
    const candidates = [vars.heap_base, allocator.heap_base, step.heap_base, 'heap_base'];
    for (const candidate of candidates) {
      const direct = parseAddr(candidate);
      if (direct !== null) return direct;
      const resolved = vars[String(candidate || '').trim()];
      const viaVar = parseAddr(resolved);
      if (viaVar !== null) return viaVar;
    }
    return null;
  }

  function configuredHeapRoots() {
    const roots = new Set(['heap_base']);
    const allocator = (state.heapState && state.heapState.allocator) || state.allocator || {};
    const raw = String(allocator.heap_base || '').trim();
    if (raw && parseAddr(raw) === null) roots.add(raw.replace(/\s+/g, ''));
    return roots;
  }

  function relativeOffset(text, fallback = null) {
    if (typeof text === 'number' && Number.isFinite(text)) return Math.trunc(text);
    const source = String(text ?? '').trim();
    if (!source) return fallback;
    const compact = source.replace(/\s+/g, '');
    const rel = /^([+-])(?:0x([0-9a-f]+)|(\d+))$/i.exec(compact);
    if (rel) {
      const value = parseAddr(compact.slice(1));
      return value === null ? fallback : (rel[1] === '-' ? -value : value);
    }
    const expr = /^([A-Za-z_]\w*)(?:([+-])(?:0x([0-9a-f]+)|(\d+)))?$/i.exec(compact);
    if (expr && configuredHeapRoots().has(expr[1])) {
      const delta = expr[3] ? parseInt(expr[3], 16) : (expr[4] ? parseInt(expr[4], 10) : 0);
      return expr[2] === '-' ? -delta : delta;
    }
    const numeric = parseAddr(source);
    if (numeric !== null) {
      const base = explicitHeapBaseValue();
      return base === null ? fallback : numeric - base;
    }
    return fallback;
  }

  function formatOffset(offset) {
    if (offset === null || offset === undefined || !Number.isFinite(offset)) return '+0x?';
    const value = Math.trunc(offset);
    const sign = value < 0 ? '-' : '+';
    return `${sign}0x${Math.abs(value).toString(16)}`;
  }

  function relAddr(text, fallbackOffset = null) {
    const offset = relativeOffset(text, fallbackOffset);
    return offset === null ? '+0x?' : formatOffset(offset);
  }

  function relRange(startText, endText, fallbackStart = null, fallbackEnd = null) {
    const s = relativeOffset(startText, fallbackStart);
    const e = relativeOffset(endText, fallbackEnd);
    if (s === null || e === null) return `${relAddr(startText, fallbackStart)} ~ ${relAddr(endText, fallbackEnd)}`;
    return `${formatOffset(s)} ~ ${formatOffset(e)}`;
  }

  function addAddressOffset(address, delta) {
    const n = parseAddr(address);
    if (n !== null) return `0x${(n + delta).toString(16)}`;
    const compact = String(address || '').replace(/\s+/g, '');
    const expr = /^([A-Za-z_]\w*)(?:([+-])(?:0x([0-9a-f]+)|(\d+)))?$/i.exec(compact);
    if (!expr) return String(address || '?');
    const base = expr[1];
    const cur = expr[3] ? parseInt(expr[3], 16) : (expr[4] ? parseInt(expr[4], 10) : 0);
    const signed = expr[2] === '-' ? -cur : cur;
    const next = signed + delta;
    if (next === 0) return base;
    return `${base}${next < 0 ? '-' : '+'}0x${Math.abs(next).toString(16)}`;
  }

  // 识别指纹哈希（cyrb53）：只用于「输入变没变」的缓存键，不是安全哈希。
  function replayHash(text) {
    const source = String(text || '');
    let h1 = 0xdeadbeef;
    let h2 = 0x41c6ce57;
    for (let index = 0; index < source.length; index += 1) {
      const ch = source.charCodeAt(index);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
  }

  function learningRevision() {
    // 学习状态修订：别名映射 / 识别规则 / HelperContract 任一变化都必须
    // 触发重新识别 —— 旧识别结果是旧知识下的产物，不允许被缓存复用。
    const contracts = (state.heapState && state.heapState.helper_contracts) || [];
    return replayHash(JSON.stringify([
      state.mappings || [],
      (state.learnedRules || []).map((rule) => [rule.rule_id, rule.enabled, rule.scope, rule.output]),
      contracts,
    ]));
  }

  /**
   * autoReplay 缓存键 = source_hash | profile_id | arch | mapping_rev | learning_rev。
   * 以前只比较 EXP 文本：版本切了、源码没变，就什么都不会重算 —— 那是
   * 假缓存。现在指纹里任何一项变化都必须重新识别、重新回放。
   */
  function replayCacheKey(text) {
    const allocator = state.allocator || {};
    const profile = allocator.profile_id
      || `v${allocator.effective_version || allocator.version || selectedGlibcVersion()}`;
    return [
      replayHash(text || ''),
      profile,
      (window.PwnApp && window.PwnApp.arch) || 'amd64',
      replayHash(JSON.stringify(state.mappings || [])),
      learningRevision(),
    ].join('|');
  }

  let autoReplayBusy = false;
  let replayPending = false;
  let lastReplayKey = null;   // 成功缓存：只有成功回放才写入，失败绝不写
  let lastFailedKey = null;   // 失败记忆：同一指纹不反复重试刷屏，任何输入变化即重试
  function autoReplayFromExp() {
    // 忙时不丢输入：标记 pending，本轮结束后立即拿最新 EXP 补跑一次，
    // 否则快速输入时 B 修改被丢弃，画布停留在旧源码状态。
    if (autoReplayBusy) { replayPending = true; return; }
    const origin = state.sceneOrigin || '';
    const expDriven = !origin || origin.startsWith('EXP') || origin.startsWith('空')
      || origin.startsWith('操作') || origin.startsWith('CANVAS') || origin.startsWith('LEARNED')
      || origin.startsWith('REPROFILE');
    if (!expDriven) return;   // 模板/场景文件是显式加载的，不被打字覆盖
    const text = (window.PwnApp && window.PwnApp.getExpText()) || '';
    const key = replayCacheKey(text);
    if (key === lastReplayKey || key === lastFailedKey) return;
    autoReplayBusy = true;
    (async () => {
      try {
        if (!text.trim()) {
          const empty = await window.pwnbao.request('heap_load', {
            scenario: { name: '空', operations: [], allocator: state.allocator || {} },
            allocator: state.allocator || {},
          });
          lastReplayKey = key;
          lastFailedKey = null;
          absorbState(empty, '空', true, { resetLayout: true });
          renderLivePanel();
          return;
        }
        const heapState = await window.pwnbao.request('heap_load', {
          source: text, allocator: state.allocator,
        });
        const changed = (heapState.steps || []).length !== state.steps.length
          || JSON.stringify(heapState.operations) !== JSON.stringify((state.heapState && state.heapState.operations) || []);
        lastReplayKey = key;
        lastFailedKey = null;
        absorbState(heapState, 'EXP 实时', true, { resetLayout: true });
        if (changed) renderLivePanel();
      } catch (error) {
        // 失败不写成功缓存：同一个输入不会无限重试，但任何输入变化（源码 /
        // profile / 学习状态）都会生成新指纹并重试。
        lastFailedKey = key;
        log(`EXP 实时识别暂不可用：${error.message}`, 'warn');
      } finally {
        autoReplayBusy = false;
        if (replayPending) {
          replayPending = false;
          autoReplayFromExp();   // 补跑被忙标志丢掉的最新输入
        }
      }
    })();
  }

  async function replayExp() {
    const text = (window.PwnApp && window.PwnApp.getExpText()) || '';
    if (!text.trim()) {
      log('exp.py 为空：先在 EXP 编辑器写内容，或直接加载模板。', 'warn');
      return;
    }
    try {
      state.allocator = buildAllocatorRequest();   // 只提交请求；机制位归后端 AllocatorProfile
      const heapState = await window.pwnbao.request('heap_load', {
        source: text,
        allocator: state.allocator,
      });
      state.scenarioName = heapState.name || 'EXP 场景';
      lastReplayKey = replayCacheKey(text);
      lastFailedKey = null;
      absorbState(heapState, 'EXP 实时识别', false, { resetLayout: true });
      switchTab('canvas');
    } catch (error) {
      log(`EXP 识别失败：${error.message}`, 'error');
      const badge = $('#heap-origin-badge');
      if (badge) {
        badge.textContent = 'EXP 失败';
        badge.title = `exp.py 未被识别为可回放操作：${error.message}`;
      }
    }
  }

  /**
   * 唯一的状态提交口。任何 edit / structural edit / EXP replay / live op /
   * runtime sync 都必须整包替换 heapState，绝不 splice 后缀进旧包：
   * 画布、operations、canonical、学习结果永远来自同一个 snapshot_id。
   */
  function commitSnapshot(heapState, origin, options = {}) {
    state.heapState = heapState;
    state.sceneOrigin = String(origin || '');
    state.steps = heapState.steps || [];
    state.learnedRules = heapState.learned_rules || [];
    state.corrections = heapState.corrections || [];
    state.episodes = heapState.episodes || [];
    state.reviews = heapState.reviews || [];                       // Agent review 标签层
    state.recognitionCorrections = heapState.recognition_corrections || [];
    state.canonicalOps = heapState.canonical_ops || [];
    state.mappings = heapState.mappings || [];
    // operations 与 steps/canonical/学习结果同包提交：state.ops 不允许任何
    // 调用点自行维护，永远来自这一个 snapshot。
    state.ops = (heapState.operations || []).map((op) => ({ ...op }));
    state.current = Number.isFinite(options.currentStep)
      ? Math.max(0, Math.min(options.currentStep, state.steps.length - 1))
      : Math.max(0, state.steps.length - 1);
    if (heapState.allocator) {
      state.allocator = heapState.allocator;
      // Truth Sync：下拉框与 ACTIVE chip 只相信后端实际生效的 profile
      //（requested ≠ effective 时 UI 显示 ⚠，绝不继续显示请求值）。
      syncGlibcSelector(heapState.allocator);
    }
    state.snapshotId = heapState.snapshot_id || `local-${++localSnapshotSeq}`;
    state.memoryRevision = heapState.memory_revision || '';
    if (options.resetLayout) state.canvasLayout.clear();
    world.clear();
    bodiesByChunk.clear();
    // rebuild with state.current already at the target step so the whole
    // prefix (and the current step) materialises as canvas bodies
    rebuildWorld();
    renderLivePanel();
    renderCanonical();
    renderRecognitionReport();
    renderLearnSummary();
    renderPending();
    // 步骤历史/解释/warning 的展示出口是 Logs/Diagnostics，画布区不放步骤卡。
    logStepContext(options.announce !== false);
    syncExpLineDecorations();
    updateOrigin(originBadge());
    if (options.announce !== false) {
      log(`堆状态已原子提交：${state.steps.length} 步 · ${originBadge()}`
        + ` · rev ${state.memoryRevision || '?'}`
        + (heapState.cache_divergence ? ` · ⚠ 缓存分歧: ${heapState.cache_divergence}` : ''));
    }
    needsDraw = true;
    binsNeedsDraw = true;
  }

  /** 兼容旧调用点：absorbState == 整包 commitSnapshot。 */
  function absorbState(heapState, origin, quiet, options = {}) {
    commitSnapshot(heapState, origin, { announce: quiet !== true, ...options });
  }

  function originBadge() {
    if (String(state.sceneOrigin || '').startsWith('STRUCTURAL')) return 'STRUCTURAL_CORRECTED';
    if (state.corrections.length) return 'CORRECTED';
    const origin = String(state.sceneOrigin || '');
    if (origin.startsWith('空')) return 'EMPTY';
    if (!origin) return 'EMPTY';
    return 'AUTHORED';
  }

  function updateOrigin(text) {
    const badge = $('#heap-origin-badge');
    if (badge) {
      badge.textContent = text;
      badge.title = `画布内容来源：${text}`
        + (state.snapshotId ? ` · snapshot ${state.snapshotId}` : '')
        + (state.memoryRevision ? ` · rev ${state.memoryRevision}` : '');
    }
  }

  function canonicalLineRows() {
    return (state.canonicalOps || [])
      .filter((op) => Number(op.source_line) > 0 && op.kind && op.kind !== 'init')
      .map((op) => ({ line: Number(op.source_line), kind: String(op.kind || ''), step: Number(op.step) || 0 }));
  }

  function currentSourceLine() {
    const op = (state.canonicalOps || []).find((item) => Number(item.step) === state.current);
    return op && Number(op.source_line) > 0 ? Number(op.source_line) : 0;
  }

  function syncExpLineDecorations(activeLine = null) {
    if (!window.PwnApp || !window.PwnApp.updateExpHeapLineDecorations) return;
    const selected = activeLine === null ? currentSourceLine() : Number(activeLine) || 0;
    window.PwnApp.updateExpHeapLineDecorations(canonicalLineRows(), selected);
  }

  function stepForSourceLine(line) {
    const selected = Number(line) || 0;
    if (!selected) return null;
    const rows = canonicalLineRows().sort((a, b) => a.line - b.line || a.step - b.step);
    const exact = rows.filter((row) => row.line === selected).pop();
    if (exact) return exact.step;
    // 选到 for/if 或空白行时，显示“执行到该源码行之前/当前位置”的最后一个堆状态。
    const before = rows.filter((row) => row.line <= selected).pop();
    return before ? before.step : 0;
  }

  function handleExpCursorLine(line) {
    const target = stepForSourceLine(line);
    syncExpLineDecorations(line);
    if (target === null || target === state.current) return;
    stepTo(target);
  }

  // =====================================================================
  // Physics world wiring

  function rebuildWorld() {
    for (let index = 0; index <= state.current; index += 1) {
      applyStepToWorld(state.steps[index], index === 0);
    }
  }

  // =====================================================================
  // PhysicalGrid — fixed cells, coverage = CoverageSpan ∩ Cell
  //
  // A chunk's visual row structure is FIXED by its physical ranges:
  //   +0x00 prev_size (one full-width cell, word bytes)
  //   +0x08 size      (one full-width cell, word bytes)
  //   +0x10 user …    (rows of two word-cells, physical ranges forever fixed)
  // An overflow never creates new rows/bars — it only paints inside the
  // cells it intersects (CoverageSpan ∩ Cell → cell-interior tint).  Long
  // chunks virtualize untouched middles; covered rows re-materialize.

  const GRID = {
    cardW: 400,
    rowH: 30,
    markerH: 18,
    titleH: 18,
    pad: 0,               // grids stack FLUSH — adjacent chunks are address-adjacent
    maxVisibleUserRows: 6,
    laneX: 148,           // grid body x; the gutter lives between 12 and laneX
    gutterW: 128,         // offset labels, drawn AFTER cells so never occluded
  };

  function chunkOffsetValue(chunk, fallback = null) {
    if (!chunk) return fallback;
    const direct = parseAddr(chunk.heap_offset);
    if (direct !== null) return direct;
    return relativeOffset(chunk.address, fallback);
  }

  const schemaWarnedSteps = new WeakSet();
  function stepChunks(step) {
    // physical_chunks 是「一次分配一张卡」的权威视图；typed_views/chunks 可能
    // 含同一 physical_id 的历史 generation。严格模式下缺失即报 schema 错误，
    // 绝不静默把 stale views 当物理内存画出来。
    if (!step) return [];
    if (Array.isArray(step.physical_chunks)) return step.physical_chunks;
    if (Array.isArray(step.chunks) && !schemaWarnedSteps.has(step)) {
      schemaWarnedSteps.add(step);
      log(`snapshot schema 不完整：step ${step.step ?? '?'} 缺少 physical_chunks，已拒绝把 typed views 当物理 chunk 绘制。请重新加载场景。`, 'error');
    }
    return [];
  }

  function chunkBodyKey(chunk) {
    return String((chunk && (chunk.physical_id || chunk.chunk_id)) || '');
  }

  function chunkLayout(step) {
    const chunks = stepChunks(step);
    let cursor = 0;
    const entries = chunks.map((chunk, index) => {
      const explicit = chunkOffsetValue(chunk, null);
      const offset = explicit === null ? cursor : explicit;
      const size = chunkSizeValue(chunk) || 0;
      if (Number.isFinite(offset)) cursor = offset + size;
      return { chunk, index, offset, size };
    });
    entries.sort((a, b) => {
      if (a.offset === null && b.offset === null) return a.index - b.index;
      if (a.offset === null) return 1;
      if (b.offset === null) return -1;
      return (a.offset - b.offset) || (a.index - b.index);
    });
    return entries;
  }

  function displayOffsetForChunk(chunk, step, fallback = null) {
    if (!chunk) return fallback;
    const direct = chunkOffsetValue(chunk, null);
    if (direct !== null) return direct;
    const body = bodiesByChunk.get(chunk.chunk_id === 'TOP' ? '__top__' : chunkBodyKey(chunk));
    if (body && body.data && Number.isFinite(body.data.heapOffset)) return body.data.heapOffset;
    const found = chunkLayout(step).find((entry) => entry.chunk.chunk_id === chunk.chunk_id);
    return found && Number.isFinite(found.offset) ? found.offset : fallback;
  }

  /**
   * PaintSpan{kind,start,end}：两种语义永远分开画。
   *   cross（CROSS_WRITE）     当前字节 provenance 被其他 writer 覆盖 → 红色斜线
   *   overlap（PHYSICAL_OVERLAP）两个有效 Typed View 共享物理范围 → 紫色反向斜线
   * 旧的 overwrite_edges 是历史 fallback，语义混杂，已删除。
   */
  function coverageSpansFor(step, chunk) {
    const spans = { cross: [], overlap: [] };
    if (!step || !chunk) return spans;
    const base = displayOffsetForChunk(chunk, step, chunkOffsetValue(chunk, null));
    const resolve = (span) => {
      let start = relativeOffset(span.physical_start, null);
      let end = relativeOffset(span.physical_end, null);
      if ((start === null || end === null) && base !== null
          && Number.isFinite(Number(span.byte_start)) && Number.isFinite(Number(span.byte_end))) {
        start = base + Number(span.byte_start);
        end = base + Number(span.byte_end);
      }
      return start !== null && end !== null && end > start ? [start, end] : null;
    };
    for (const span of step.paint_spans || []) {
      if (span.object_id !== chunk.physical_id) continue;
      if (span.visual_kind !== 'cross_write' && span.visual_kind !== 'physical_overlap') continue;
      const range = resolve(span);
      if (!range) continue;
      if (span.visual_kind === 'physical_overlap') spans.overlap.push(range);
      else spans.cross.push(range);
    }
    return spans;
  }

  function coveredSubRanges(cellStart, cellEnd, spans) {
    if (cellStart === null || cellEnd === null) return [];
    const parts = [];
    for (const [start, end] of spans) {
      const left = Math.max(start, cellStart);
      const right = Math.min(end, cellEnd);
      if (right > left) parts.push([left, right]);
    }
    // merge overlaps so hatching never double-draws
    parts.sort((a, b) => a[0] - b[0]);
    const merged = [];
    for (const part of parts) {
      const last = merged[merged.length - 1];
      if (last && part[0] <= last[1]) last[1] = Math.max(last[1], part[1]);
      else merged.push([part[0], part[1]]);
    }
    return merged;
  }

  /**
   * Build the fixed PhysicalGrid rows for one chunk.  Returns geometry +
   * row model used by BOTH physics sizing and drawing so they never drift.
   *
   * 两种模式：
   *   collapsed（普通模式） 内部行折叠成 ⋯ marker，视觉紧凑；
   *   fullRows（编辑模式）  每个物理 row 都是真实可寻址项 —— 只做渲染
   *                         虚拟化（draw 时按视口裁剪），绝不做语义虚拟化
   *                         （不把真实行合并成不可编辑的 marker）。
   * extent 非整行时最后一行是 partial row：多出的 cell 无物理字节。
   */
  function buildChunkGrid(chunk, step, options = {}) {
    const fullRows = Boolean(options.fullRows);
    const word = archWord();
    const userRowBytes = word * 2;
    const base = displayOffsetForChunk(chunk, step, 0);
    const spans = step ? coverageSpansFor(step, chunk) : { cross: [], overlap: [] };
    const allSpans = [...spans.cross, ...spans.overlap];
    const triple = chunkSizeTriple(chunk);
    const isTop = chunk.view_kind === 'top_chunk';
    const extent = triple.physicalExtentSize || 0x20;
    const size = Number.isFinite(extent) && extent > 0 ? extent : 0x20;
    const userBytes = Math.max(0, size - word * 2);
    // the top-chunk typed view only exposes prev_size/size/end — no user rows
    const totalUserRows = isTop ? 0 : Math.max(0, Math.ceil(userBytes / userRowBytes));
    // a corrupted size can claim astronomically many rows; the grid renders
    // (and scans for coverage) a bounded window and virtualizes the rest
    const rowLimit = Math.min(totalUserRows, 4096);

    const coveredRowIndexes = new Set();
    if (base !== null) {
      for (let index = 0; index < rowLimit; index += 1) {
        const start = base + word * 2 + index * userRowBytes;
        if (coveredSubRanges(start, start + userRowBytes, allSpans).length) {
          coveredRowIndexes.add(index);
        }
      }
    }

    const rows = [];
    // prev_size + size 合并为同一行两格（与 user 行同为 16 字节行，右缘对齐）
    rows.push({ kind: 'header', name: 'prev_size|size', off: 0, full: false });

    const keepVisible = new Set();
    let hiddenBytes = 0;
    let lastWasMarker = false;
    if (fullRows) {
      // 编辑模式：不折叠 —— rowLimit 内每个物理行都是独立可编辑项
      for (let index = 0; index < rowLimit; index += 1) {
        rows.push({ kind: 'user', index, off: word * 2 + index * userRowBytes });
      }
      lastWasMarker = false;
    } else {
      for (const index of coveredRowIndexes) keepVisible.add(index);
      for (let index = 0; index < rowLimit; index += 1) {
        const isEdge = index < 2 || index >= rowLimit - 1;
        if (totalUserRows <= GRID.maxVisibleUserRows || isEdge || keepVisible.has(index)) {
          const off = word * 2 + index * userRowBytes;
          rows.push({ kind: 'user', index, off });
          lastWasMarker = false;
        } else {
          hiddenBytes += userRowBytes;
          if (!lastWasMarker) {
            rows.push({ kind: 'marker', bytes: 0 });
            lastWasMarker = true;
          }
        }
      }
    }
    // 当 totalUserRows 超出扫描窗口（size 已被覆盖成天文数字），最后一个
    // "尾行" 是窗口边界而不是真实 chunk 末尾 —— 用诚实的截断标记替代。
    const truncated = totalUserRows > rowLimit;
    if (truncated && rows.length && rows[rows.length - 1].kind === 'user') {
      rows.pop();
      hiddenBytes += userRowBytes;
    }
    if (truncated && !rows.some((row) => row.kind === 'marker')) {
      rows.push({ kind: 'marker', bytes: 0 });
    }

    const markers = rows.filter((row) => row.kind === 'marker').length;
    if (hiddenBytes && markers) {
      const marker = rows.find((row) => row.kind === 'marker');
      if (marker) marker.bytes = hiddenBytes;
    }
    const solidRows = rows.length - markers;
    const height = GRID.titleH + solidRows * GRID.rowH + markers * GRID.markerH;
    return { rows, height, word, userRowBytes, base, spans, size, truncated, userBytes, fullRows };
  }

  /**
   * buildChunkGrid 结果缓存：同一 step × chunk 对象的 rows/height/spans
   * 是纯几何模型，滚动/hover/命中测试期间不允许反复重建（覆盖扫描上限
   * 4096 行，复杂 chunk 重复构建是滚动热路径的大头）。step/chunk 对象由
   * commitSnapshot 整包替换，WeakMap 自动失效，不存在跨 snapshot 复用。
   * collapsed / fullRows 两种模式各存一份。
   */
  function cachedChunkGrid(chunk, step, fullRows = false) {
    if (!chunk || !step) return buildChunkGrid(chunk, step);
    let perStep = chunkGridCache.get(step);
    if (!perStep) {
      perStep = new Map();
      chunkGridCache.set(step, perStep);
    }
    let entry = perStep.get(chunk);
    if (!entry) {
      entry = {};
      perStep.set(chunk, entry);
    }
    const slot = fullRows ? 'full' : 'collapsed';
    if (!entry[slot]) entry[slot] = buildChunkGrid(chunk, step, { fullRows });
    return entry[slot];
  }

  function gridHeight(chunk, step, fullRows = false) {
    return cachedChunkGrid(chunk, step, fullRows).height;
  }

  function fieldAtOffset(chunk, offset) {
    if (offset === null || offset === undefined) return null;
    return (chunk.fields || []).find((item) => relativeOffset(item.address, null) === offset) || null;
  }

  function cellValue(chunk, grid, cellStart, cellIndex) {
    const field = fieldAtOffset(chunk, cellStart);
    if (field) {
      return { value: field.value, provenance: field.provenance, name: field.name, field };
    }
    const region = (chunk.regions || []).find((item) => {
      if (grid.base === null || cellStart === null) return false;
      const start = grid.base + (Number(item.start) || 0);
      return start <= cellStart && start + (Number(item.end) - Number(item.start)) > cellStart;
    });
    if (region && region.state === 'known' && region.value) {
      return { value: region.value, provenance: region.provenance || 'derived', name: '', field: null };
    }
    if (region && region.state === 'zero') {
      return { value: '0x0', provenance: 'derived', name: `qword ${cellIndex}`, field: null };
    }
    return {
      value: 'unknown',
      provenance: 'unknown',
      name: cellStart !== null ? `qword @ ${formatOffset(cellStart)}` : `qword ${cellIndex}`,
      field: null,
    };
  }

  function applyStepToWorld(step, reset) {
    void reset;
    // 物理堆是一段连续内存：chunk 的大地址/位置优先用 snapshot.heap_offset，
    // 缺失时按上一 chunk 的 size 顺序累计；绝不靠假 heap base 排序。
    // 布局完全确定性：不跑物理步进，位置直接写入。编辑模式下每个 chunk
    // 底边留出 + 手柄的半圆空间（这只是画布间距，物理 offset 仍由 snapshot 决定）。
    const laneGap = state.editMode ? 14 : 0;
    let laneY = 96;
    const sorted = chunkLayout(step);
    for (const entry of sorted) {
      const chunk = entry.chunk;
      const bodyKey = chunkBodyKey(chunk);
      let body = bodiesByChunk.get(bodyKey);
      const isTop = chunk.view_kind === 'top_chunk';
      // 先写 body.data.heapOffset 再算 grid：displayOffsetForChunk 的 body
      // fallback 必须在本 step 内看到确定的 offset，缓存与否结果一致。
      if (body) body.data.heapOffset = entry.offset;
      const height = gridHeight(chunk, step, state.editMode);
      // LEGACY-ONLY：visual_y 只为旧场景文件保留读取（新会话无写入方，
      // 此表恒空，chunk 一律落在 laneY）——训练截图不受旧布局影响。
      const storedY = state.canvasLayout.get(bodyKey);
      const y = Number.isFinite(storedY) ? storedY : laneY;
      if (!body) {
        body = world.addBody({
          x: GRID.laneX,
          y,
          w: GRID.cardW,
          h: height,
          noCollide: true,
          data: { kind: 'chunk' },
        });
        bodiesByChunk.set(bodyKey, body);
      } else {
        body.y = y;
        body.h = height;
      }
      body.data.chunk = chunk;
      body.data.heapOffset = entry.offset;
      laneY = y + height + (structurallyEditableChunk(chunk) ? laneGap : 0);
    }
    // top chunk card — allocator truth lives in step.top, not in chunks
    const topKey = '__top__';
    const lastEntry = sorted[sorted.length - 1];
    const fallbackTopOffset = lastEntry && Number.isFinite(lastEntry.offset)
      ? lastEntry.offset + (lastEntry.size || 0)
      : relativeOffset(step.top && step.top.address, 0);
    const topOffset = relativeOffset(step.top && step.top.address, fallbackTopOffset);
    const topWord = archWord();
    const topChunk = {
      chunk_id: 'TOP',
      physical_id: '__top__',
      address: (step.top && step.top.address) || '?',
      user_address: '',
      chunk_size: String((step.top && step.top.size) || '?'),
      heap_offset: Number.isFinite(topOffset) ? `0x${topOffset.toString(16)}` : '',
      request_size: '',
      lifecycle: 'top',
      bin_location: 'top',
      menu_indexes: [],
      aliases: [],
      view_kind: 'top_chunk',
      evidence_level: '',
      provenance: (step.top && step.top.provenance) || 'derived',
      fields: [
        {
          name: 'prev_size',
          value: 'unknown',
          address: (step.top && step.top.address) || '?',
          provenance: 'unknown',
        },
        {
          name: 'size',
          value: String((step.top && step.top.size) || '?'),
          address: step.top && step.top.address ? addAddressOffset(step.top.address, topWord) : '?',
          provenance: (step.top && step.top.provenance) || 'derived',
        },
      ],
    };
    const topHeight = gridHeight(topChunk, step, state.editMode);
    const topStoredY = state.canvasLayout.get(topKey);
    const topY = Number.isFinite(topStoredY) ? topStoredY : laneY;
    let topBody = bodiesByChunk.get(topKey);
    if (topBody) topBody.data.heapOffset = topOffset;
    if (!topBody) {
      topBody = world.addBody({
        x: GRID.laneX, y: topY, w: GRID.cardW, h: topHeight,
        noCollide: true,
        data: { kind: 'chunk' },
      });
      bodiesByChunk.set(topKey, topBody);
    } else {
      topBody.y = topY;
      topBody.h = topHeight;
    }
    topBody.data.chunk = topChunk;
    topBody.data.heapOffset = topOffset;
    // remove chunks that disappeared (top card always stays)
    const alive = new Set([...stepChunks(step).map(chunkBodyKey), topKey]);
    for (const [chunkId, body] of [...bodiesByChunk]) {
      if (!alive.has(chunkId)) {
        world.removeBody(body);
        bodiesByChunk.delete(chunkId);
      }
    }
    invalidateHeapBounds();
    state.camera.y = clampVerticalScroll(state.camera.y);
  }

  // =====================================================================
  // Timeline / step navigation

  function stepTo(index) {
    index = Math.max(0, Math.min(state.steps.length - 1, index));
    if (index < state.current) {
      // rewinding: simplest honest model is a full rebuild
      state.current = 0;
      world.clear();
      bodiesByChunk.clear();
      for (let i = 0; i <= index; i += 1) applyStepToWorld(state.steps[i], i === 0);
    } else {
      for (let i = state.current + 1; i <= index; i += 1) applyStepToWorld(state.steps[i], false);
    }
    state.current = index;
    state.camera.y = clampVerticalScroll(state.camera.y);
    renderLivePanel();
    logStepContext(true);   // 用户跳步：解释/警告进 Logs，画布区不放步骤卡
    syncExpLineDecorations();
    updateOrigin(originBadge());
    needsDraw = true;
    binsNeedsDraw = true;
  }

  window.PwnHeapDebugAdvance = (n) => stepTo(Math.min(state.steps.length - 1, state.current + (n || 1)));

  // =====================================================================
  // Left column renderers

  function renderLivePanel() {
    // Heap 左栏只保留「当前操作」：malloc/free/edit/show 表单。
    // 历史步骤/解释/warning 一律进 Logs/Diagnostics，不再渲染时间线与步骤列表。
    const host = $('#heap-live-ops');
    if (!host) return;
    host.innerHTML = `
      <div class="live-ops">
        <div class="sidebar-mini-title">操作（用户操作 glibc，不是图）</div>
        <div class="live-op-tabs">
          ${['malloc', 'free', 'edit', 'show'].map((k) =>
            `<button class="mini-btn live-op-tab ${state.liveOpKind === k ? 'active' : ''}" data-kind="${k}">${k}</button>`).join('')}
        </div>
        <div id="live-op-form" class="live-op-form"></div>
        <button id="live-op-run" class="btn mini-btn primary" style="width:100%">执行</button>
        <div id="live-op-result" class="live-op-result"></div>
      </div>`;
    // 「执行」按钮必须可点击（此前只有表单 Enter 键绑定过 executeLiveOp）。
    const run = host.querySelector('#live-op-run');
    if (run) run.addEventListener('click', executeLiveOp);
    renderLiveOps();
  }

  // =====================================================================
  // 活操作表单：malloc/free/edit/show → heap_operation（HeapOperation → 引擎 → snapshot）

  function currentChunkOptions() {
    const step = state.steps[state.current];
    if (!step) return [];
    return stepChunks(step)
      .filter((chunk) => chunk.lifecycle !== 'top')
      .map((chunk) => chunk.chunk_id);
  }

  function renderLiveOps() {
    const host = $('#live-op-form');
    if (!host) return;
    state.liveOpKind = state.liveOpKind || 'malloc';
    const kind = state.liveOpKind;
    const chunks = currentChunkOptions();
    const chunkSelect = (id) => `
      <label class="form-row"><span>Chunk</span>
        <select id="${id}" class="input">${chunks.map((c) => `<option${c === state.liveOpChunk ? ' selected' : ''}>${esc(c)}</option>`).join('') || '<option value="">（先 malloc）</option>'}</select></label>`;
    if (kind === 'malloc') {
      host.innerHTML = `
        <label class="form-row"><span>请求大小</span><input id="live-size" class="input" placeholder="0x80" /></label>
        <label class="form-row"><span>填充数据</span><input id="live-fill" class="input" placeholder="AAAAAAAAAAAAAAAA" /></label>
        <label class="form-row"><span>标签</span><input id="live-label" class="input" placeholder="留空自动 A/B/C…" /></label>`;
    } else if (kind === 'edit') {
      host.innerHTML = `
        ${chunkSelect('live-chunk')}
        <label class="form-row"><span>Offset</span><input id="live-offset" class="input" placeholder="0x78（越界即跨写）" /></label>
        <label class="form-row"><span>Data</span><input id="live-data" class="input" placeholder="p64(0x91) 或 b'AAAA'" /></label>`;
    } else {
      host.innerHTML = chunkSelect('live-chunk');
    }
    host.querySelectorAll('.form-row input').forEach((input) => {
      input.addEventListener('keydown', (event) => { if (event.key === 'Enter') executeLiveOp(); });
    });
    const size = $('#live-size');
    if (size && !size.value) size.value = '0x80';
  }

  async function executeLiveOp() {
    const kind = state.liveOpKind || 'malloc';
    const payload = { kind };
    if (kind === 'malloc') {
      payload.request_size = ($('#live-size')?.value || '').trim() || '0x18';
      payload.data = ($('#live-fill')?.value || '').trim();
      payload.label = ($('#live-label')?.value || '').trim();
    } else {
      const chunkSelect = $('#live-chunk');
      payload.chunk = chunkSelect?.value || state.liveOpChunk || '';
      state.liveOpChunk = payload.chunk;
      if (kind === 'edit') {
        payload.offset = ($('#live-offset')?.value || '0').trim() || '0';
        payload.data = ($('#live-data')?.value || '').trim();
      }
    }
    try {
      const heapState = await window.pwnbao.request('heap_operation', payload);
      absorbState(heapState, `操作 ${kind}`);
      const info = heapState.appended_operation || {};
      const lines = [
        info.title || `${kind} 已执行`,
        ...(info.explanation || []),
        ...(info.warnings || []).map((w) => `⚠ [${w.severity}] ${w.code} ${w.title}：${w.message}`),
      ];
      const host = $('#live-op-result');
      if (host) {
        host.innerHTML = lines.map(() => '<div class="live-op-line"></div>').join('');
        const nodes = host.querySelectorAll('.live-op-line');
        lines.forEach((line, index) => {
          nodes[index].textContent = line;
          nodes[index].classList.toggle('warn', line.startsWith('⚠'));
        });
      }
      // Semantic Round Trip：操作同步写进 EXP —— EXP 与画布互为投影，永远一致。
      // 生成走后端 HelperContract（live_op_python）；不可证明就不写，绝不硬编码。
      const expLine = await canonicalExpLine(kind, payload, info);
      if (expLine) await app().insertExpText(`${expLine}
`);
      log(`堆操作已执行：${info.title || kind}${expLine ? '（已同步写入 EXP）' : ''}`);
    } catch (error) {
      const host = $('#live-op-result');
      if (host) {
        host.innerHTML = '<div class="live-op-line warn"></div>';
        host.querySelector('.live-op-line').textContent = `✗ ${error.message}`;
      }
      log(`堆操作失败：${error.message}`, 'error');
    }
  }

  /**
   * 前端只提交 Canonical Operation；EXP 行由 Python 按已确认 HelperContract
   * 生成。返回 safe=false 时显示「不可安全回写 EXP」，绝不把猜出来的
   * add/delete/edit 塞进用户源码。
   */
  async function canonicalExpLine(kind, payload, info) {
    let label = payload.label || payload.chunk || '';
    const titleMatch = /\w+\((\w+),/.exec(String((info && info.title) || ''));
    if (kind === 'malloc' && titleMatch) label = titleMatch[1];
    try {
      const result = await window.pwnbao.request('heap_canonical_python', {
        kind,
        chunk: label,
        request_size: payload.request_size || '',
        data: payload.data || '',
        offset: payload.offset || '',
      });
      if (result && result.safe && result.python) return result.python;
      log(`不可安全回写 EXP：${(result && result.reason) || 'helper 契约未确认'}（引擎已执行，但不改 exp.py）`, 'warn');
      return '';
    } catch (error) {
      log(`不可安全回写 EXP：${error.message}`, 'warn');
      return '';
    }
  }


  // ---------------------------------------------------------------------
  // 学习状态摘要：识别规则 / 校正 / 别名映射只占一行 + 可折叠映射表单。
  // （旧的 renderRules/renderCorrections/renderMappings 大块视图没有入口，
  //   属于死代码 —— 细节走日志面板，这里只保留可操作的最小集合。）
  function renderLearnSummary() {
    const host = $('#heap-learn-summary');
    if (!host) return;
    const rules = state.learnedRules || [];
    const corrections = state.corrections || [];
    const mappings = state.mappings || [];
    const reviews = state.reviews || [];
    const labeled = (state.recognitionCorrections || []).length;
    const latestEpisode = (state.episodes || []).slice(-1)[0];
    host.innerHTML = `
      <div class="heap-learn-summary">
        <div class="sidebar-mini-title" style="margin-top:12px">识别状态</div>
        <div class="hint-dim">
          规则 ${rules.length} 条 · 校正 ${corrections.length} 条 · 别名映射 ${mappings.length} 条 · 候选标注 ${labeled} 条
          ${latestEpisode ? ` · 最近：${esc(latestEpisode.field_name)} ${esc(latestEpisode.before_value)} → ${esc(latestEpisode.after_value)}（${esc(latestEpisode.intent_label || latestEpisode.inferred_intent || '')}）` : ''}
        </div>
        ${corrections.length ? '<button id="heap-undo" class="btn mini-btn" style="margin-top:6px">撤销最后一次画布校正</button>' : ''}
        <div class="cli-row" style="margin-top:8px">
          <button id="heap-export-case" class="btn mini-btn" title="按固定 schema 导出训练 case（engine/recognizer/allocator revision 一并保存；写进 generated/）">导出训练 Case</button>
          <button id="heap-import-review" class="btn mini-btn" title="导入外部 Agent 审查（review/ 层，独立标签，绝不覆盖当前 Snapshot）">导入 Agent Review</button>
        </div>
        ${reviews.length ? `
          <details class="heap-mapping-details">
            <summary>Agent Reviews（${reviews.length}）</summary>
            ${reviews.map((review) => `
              <div class="mapping-row">
                <span class="mono">${esc(review.review_id)}</span>
                <span class="mapping-target">${esc(review.issue_type || '')}</span>
                <span class="rec-verdict rec-verdict-${esc(review.verdict || 'proposed')}">${esc(review.verdict || 'proposed')}</span>
                <span class="flex-spacer"></span>
                ${['proposed', 'validated'].includes(review.verdict)
                  ? `<button class="mini-btn review-apply" data-id="${esc(review.review_id)}" data-confirm="${review.verdict === 'validated' ? '1' : ''}">${review.verdict === 'validated' ? '人工确认收下' : '验证'}</button>` : ''}
              </div>`).join('')}
          </details>` : ''}
        <details class="heap-mapping-details">
          <summary>别名映射（addchunk → add 之类的用户词典）</summary>
          <div class="mapping-rows">
            ${mappings.length ? mappings.map((m) => `
              <div class="mapping-row">
                <span class="mono">${esc(m.alias)}</span>
                <span class="mapping-arrow">→</span>
                <span class="mapping-target">${esc(m.target)}</span>
                ${m.roles ? `<span class="mapping-roles">(${esc(rolesSlotText(m.roles))})</span>` : ''}
                <span class="flex-spacer"></span>
                <button class="mini-btn mapping-del" data-alias="${esc(m.alias)}">删除</button>
              </div>`).join('')
        : '<div class="hint-dim">暂无映射。自定义函数名映射到标准语义后，识别立即重算。</div>'}
          </div>
          <div class="mapping-form">
            <label class="form-row"><span>函数名</span><input id="map-alias" class="input" placeholder="addchunk" /></label>
            <label class="form-row"><span>语义</span>
              <select id="map-target" class="input">
                <option value="alloc">add（分配）</option>
                <option value="free">free（释放）</option>
                <option value="edit">edit（编辑）</option>
                <option value="show">show（查看）</option>
                <option value="copy">copy（复制）</option>
              </select></label>
            <label class="form-row"><span>参数角色</span><input id="map-roles" class="input" placeholder="可选：index,size,data" /></label>
            <button id="map-add" class="btn primary" style="width:100%">添加映射并重算</button>
          </div>
        </details>
      </div>`;
    host.querySelectorAll('.mapping-del').forEach((button) => {
      button.addEventListener('click', async () => {
        try {
          const result = await window.pwnbao.request('heap_mapping', {
            action: 'remove', alias: button.dataset.alias,
          });
          absorbState(result, 'MAPPING');
        } catch (error) {
          log(`删除映射失败：${error.message}`, 'error');
        }
      });
    });
    const undo = host.querySelector('#heap-undo');
    if (undo) undo.addEventListener('click', undoCorrection);
    const exportCase = host.querySelector('#heap-export-case');
    if (exportCase) exportCase.addEventListener('click', exportTrainingCase);
    const importReview = host.querySelector('#heap-import-review');
    if (importReview) importReview.addEventListener('click', importAgentReview);
    host.querySelectorAll('.review-apply').forEach((button) => {
      button.addEventListener('click', () => applyAgentReview(button.dataset.id, button.dataset.confirm === '1'));
    });
    const add = host.querySelector('#map-add');
    if (add) {
      add.addEventListener('click', async () => {
        const alias = host.querySelector('#map-alias').value.trim();
        const target = host.querySelector('#map-target').value;
        const roles = host.querySelector('#map-roles').value.trim();
        if (!alias) { log('函数名为空。', 'warn'); return; }
        try {
          const result = await window.pwnbao.request('heap_mapping', {
            action: 'add', alias, target, roles,
          });
          absorbState(result, 'MAPPING');
          log(`映射已生效：${alias} → ${target}，识别已重算（${result.steps.length} 步）`);
        } catch (error) {
          log(`添加映射失败：${error.message}`, 'error');
        }
      });
    }
  }

  // ---------------------------------------------------------------------
  // 操作流程（Canonical IR 视图）—— EXP 与画布共用的同一操作模型
  const KIND_ICONS = { alloc: '▲', free: '▼', edit: '✎', show: '○', init: '○' };

  function renderCanonical() {
    const host = $('#heap-canonical');
    if (!host) return;
    const ops = state.canonicalOps || [];
    if (!ops.length) { host.innerHTML = ''; return; }
    host.innerHTML = `
      <div class="sidebar-mini-title">操作流程（Canonical IR · 双向定位）</div>
      <div class="canonical-list">
        ${ops.map((op) => `
          <button class="canonical-row ${op.step === state.current ? 'active' : ''}" data-step="${op.step}" data-chunk="${esc((op.effects || []).find((e) => e.kind === 'alloc')?.chunk || op.chunk || '')}">
            <span class="cl-step">#${op.step}</span>
            <span class="cl-kind">${KIND_ICONS[op.kind] || '·'} ${esc(op.kind)}</span>
            <span class="cl-title"></span>
          </button>`).join('')}
      </div>
      <div id="heap-locate-body"></div>`;
    const titles = host.querySelectorAll('.cl-title');
    ops.forEach((op, index) => {
      const effect = (op.effects || [])[0];
      let detail = op.title || op.kind;
      if (effect) {
        if (effect.kind === 'alloc') detail = `→ chunk ${effect.chunk} @ ${effect.user_pointer}`;
        else if (effect.kind === 'free') detail = `→ ${effect.destination}`;
        else if (effect.kind === 'write') detail = `→ ${effect.chunk}.${effect.field}`;
      }
      titles[index].textContent = detail;
    });
    host.querySelectorAll('.canonical-row').forEach((row) => {
      row.addEventListener('click', () => {
        stepTo(Number(row.dataset.step));
        const chunkId = row.dataset.chunk;
        if (chunkId) {
          selectChunkById(chunkId);
          locateChunk(chunkId);
        }
        needsDraw = true;
      });
    });
  }

  const RECOGNITION_VERDICT_ICONS = { ambiguous: '⚠', unknown: '?', ignored: '○' };
  const RECOGNITION_LABEL_KINDS = ['alloc', 'free', 'edit', 'show', 'copy'];
  const RECOGNITION_ROLE_OPTIONS = ['index', 'size', 'data'];

  /** 角色槽位 → 展示文本：null 槽显示为「?」，位置一目了然（index,?,data）。 */
  function rolesSlotText(roles) {
    let slots = [];
    if (roles && typeof roles === 'object' && !Array.isArray(roles)) {
      slots = Object.keys(roles).sort((a, b) => Number(a.replace('arg', '')) - Number(b.replace('arg', '')))
        .map((key) => roles[key]);
    } else if (Array.isArray(roles)) {
      slots = roles;
    } else {
      return String(roles || '');
    }
    return slots.map((role) => role || '?').join(',');
  }

  /**
   * RecognitionReport：识别失败是一等数据。只展示 canonical 列表时你只能
   * 看到「识别出了 8 步」，却不知道源码里其实有 11 个候选调用 —— 这里把
   * 后端报告的 ambiguous / unknown / ignored 逐条亮出来（含语义评分），
   * 并允许就地标注（语义 + 参数角色 → RecognitionCorrection，≠ 画布校正），
   * 不用再绕道「别名映射」。点行跳源码行。
   */
  function renderRecognitionReport() {
    const host = $('#heap-recognition');
    if (!host) return;
    const report = ((state.heapState || {}).analysis || {}).recognition || {};
    const total = Number(report.candidate_calls) || 0;
    if (!total) { host.innerHTML = ''; return; }
    const recognized = Number(report.recognized) || 0;
    const ambiguous = Number(report.ambiguous) || 0;
    const unknown = Number(report.unknown) || 0;
    const ignored = Number(report.ignored) || 0;
    const scoresText = (candidate) => {
      const scores = candidate.scores || {};
      const parts = Object.entries(scores)
        .sort((a, b) => b[1] - a[1])
        .map(([kind, score]) => `${kind} ${score}`);
      return parts.length ? ` · 语义评分 ${parts.join(' / ')}` : '';
    };
    const unbound = (report.candidates || []).filter((candidate) => candidate.verdict !== 'recognized');
    // 参数位数量来自识别报告的 argument_count（真实调用实参数），不再固定 3。
    const argCountFor = (candidate) => Math.min(6, Math.max(1, Number(candidate.argument_count) || 3));
    host.innerHTML = `
      <div class="sidebar-mini-title">识别质量</div>
      <div class="hint-dim">识别 ${recognized}/${total}${ambiguous ? ` · ⚠ ${ambiguous} ambiguous` : ''}${unknown ? ` · ? ${unknown} unknown` : ''}${ignored ? ` · ○ ${ignored} ignored` : ''}</div>
      ${unbound.length ? `
        <details class="heap-mapping-details" open>
          <summary>${unbound.length} 个调用未绑定语义（直接标注 → RecognitionCorrection）</summary>
          ${unbound.map((candidate, index) => `
            <div class="rec-item" data-index="${index}">
              <button class="canonical-row rec-row" data-line="${Number(candidate.line) || 0}">
                <span class="cl-step">L${Number(candidate.line) || 0}</span>
                <span class="cl-kind">${RECOGNITION_VERDICT_ICONS[candidate.verdict] || '·'} ${esc(candidate.verdict)}</span>
                <span class="cl-title">${esc(candidate.source_text || candidate.function || '')}</span>
              </button>
              <div class="rec-reason hint-dim">${esc(candidate.reason || '')}${scoresText(candidate)}</div>
              <div class="rec-label-row">
                ${RECOGNITION_LABEL_KINDS.map((kind) => `<button class="mini-btn rec-sem" data-sem="${kind}">${kind}</button>`).join('')}
                <button class="mini-btn rec-sem" data-sem="ignore">○忽略</button>
                ${Array.from({ length: argCountFor(candidate) }, (_, arg) => `<select class="input rec-role" data-arg="${arg}" title="arg${arg} 的参数角色（留空 = 未知，位置仍保留）">
                  <option value="">arg${arg}</option>
                  ${RECOGNITION_ROLE_OPTIONS.map((role) => `<option value="${role}">${role}</option>`).join('')}
                </select>`).join('')}
                <button class="mini-btn primary rec-confirm">确认</button>
              </div>
            </div>`).join('')}
        </details>` : ''}
    `;
    host.querySelectorAll('.rec-row').forEach((row) => {
      row.addEventListener('click', () => {
        const line = Number(row.dataset.line) || 0;
        syncExpLineDecorations(line);
        const target = stepForSourceLine(line);
        if (target !== null) stepTo(target);
        needsDraw = true;
      });
    });
    host.querySelectorAll('.rec-item').forEach((item) => {
      const candidate = unbound[Number(item.dataset.index) || 0] || {};
      let semantic = '';
      item.querySelectorAll('.rec-sem').forEach((button) => {
        button.addEventListener('click', () => {
          semantic = button.dataset.sem;
          item.querySelectorAll('.rec-sem').forEach((other) => other.classList.toggle('active', other === button));
        });
      });
      const confirm = item.querySelector('.rec-confirm');
      if (confirm) {
        confirm.addEventListener('click', async () => {
          if (!semantic) { log('先选择语义（alloc/free/edit/show/copy/忽略）。', 'warn'); return; }
          // 参数角色必须保留位置：arg0 未知也要以 null 上送，
          // 绝不能 filter(Boolean) 后让 arg1 错位成 arg0 —— 那是训练集致命错标。
          const roles = {};
          item.querySelectorAll('.rec-role').forEach((select) => {
            roles[`arg${select.dataset.arg}`] = select.value || null;
          });
          try {
            const result = await window.pwnbao.request('heap_label_candidate', {
              line: Number(candidate.line) || 0,
              function: candidate.function || '',
              semantic,
              roles,
              source_text: candidate.source_text || '',
            });
            absorbState(result, 'LEARNED 标注');
            const correction = result.recognition_correction || {};
            const boundRoles = Object.entries(correction.roles || {})
              .filter(([, role]) => role)
              .map(([arg, role]) => `${arg}=${role}`);
            log(`识别标注已生效：L${correction.source_line} ${correction.function} → ${correction.semantic}`
              + (boundRoles.length ? `（${boundRoles.join(', ')}）` : '') + ' · 识别已重算');
          } catch (error) {
            log(`识别标注失败：${error.message}`, 'error');
          }
        });
      }
    });
  }

  /** chunk_id → 当前 step 里实体的稳定 physical_id（缺省回退 chunk_id）。 */
  function selectChunkById(chunkId) {
    const step = state.steps[state.current];
    const chunk = stepChunks(step).find((item) => item.chunk_id === chunkId)
      || stepChunks(step).find((item) => (item.aliases || []).includes(chunkId));
    state.selectedPhysicalId = chunk ? chunkBodyKey(chunk) : chunkId;
    needsDraw = true;
  }

  async function locateChunk(chunkId) {
    try {
      const result = await window.pwnbao.request('heap_chunk_history', {
        chunk: chunkId, upto: state.current,
      });
      const body = $('#heap-locate-body');
      if (!body) return;
      body.innerHTML = `
        <div class="sidebar-mini-title">chunk ${esc(chunkId)} 生命周期（点行跳转）</div>
        ${(result.history || []).map((item) => `
          <button class="canonical-row" data-step="${item.step}">
            <span class="cl-step">#${item.step}</span>
            <span class="cl-kind">${KIND_ICONS[item.kind] || '·'} ${item.kind}</span>
            <span class="cl-title">${esc(item.summary)}</span>
          </button>`).join('')}`;
      body.querySelectorAll('.canonical-row').forEach((row) => {
        row.addEventListener('click', () => stepTo(Number(row.dataset.step)));
      });
    } catch (error) {
      log(`chunk 历史加载失败：${error.message}`, 'error');
    }
  }

  async function locateField(address) {
    try {
      const result = await window.pwnbao.request('heap_field_provenance', {
        step: state.current, address,
      });
      const body = $('#heap-locate-body');
      if (!body) return;
      const chain = result.chain || [];
      const last = chain[chain.length - 1];
      body.innerHTML = `
        <div class="sidebar-mini-title">字段溯源 @ ${esc(address)}</div>
        ${chain.slice().reverse().map((item) => `
          <button class="canonical-row" data-step="${item.step}">
            <span class="cl-step">#${item.step}</span>
            <span class="cl-kind">${item.kind === 'alloc' ? '▲' : '✎'}</span>
            <span class="cl-title">${esc(item.summary)}${item.value ? ` ← ${esc(item.value)}` : ''}</span>
          </button>`).join('') || '<div class="hint-dim">无记录。</div>'}
        ${last ? `<div class="hint-dim">当前值来源：${esc(last.summary)}（Operation #${last.step}）</div>` : ''}`;
      body.querySelectorAll('.canonical-row').forEach((row) => {
        row.addEventListener('click', () => stepTo(Number(row.dataset.step)));
      });
    } catch (error) {
      log(`字段溯源失败：${error.message}`, 'error');
    }
  }

  // ---------------------------------------------------------------------
  // Pending step：画布物理写入 → 反向求解 → 待应用步骤（写入 EXP / 仅用于推演）

  function renderPending() {
    const host = $('#heap-pending');
    if (!host) return;
    const pending = state.pendingStep;
    if (!pending) { host.hidden = true; host.innerHTML = ''; return; }
    const stepRows = (state.canonicalOps || [])
      .filter((op) => op.kind !== 'init')
      .map((op) => `<div class="pending-exp-row">#${op.step} ${esc(op.source_call || op.title || op.kind)}</div>`)
      .join('');
    host.hidden = false;
    host.innerHTML = `
      <div class="pending-block">
        <div class="pending-head">原 EXP</div>
        <div class="pending-orig">${stepRows || '<span class="hint-dim">（空）</span>'}</div>
        <div class="pending-head">画布产生的操作（待应用）</div>
        <pre class="pending-code">${esc(pending.python)}</pre>
        <div class="hint-dim">${esc(pending.effectsText)}</div>
        <div class="cli-row">
          <button id="pending-write" class="btn primary">写入 EXP</button>
          <button id="pending-simulate" class="btn">仅用于推演</button>
          <button id="pending-discard" class="btn">丢弃</button>
        </div>
      </div>`;
    $('#pending-write').addEventListener('click', async () => {
      await app().insertExpText(`${pending.python}\n`);
      state.pendingStep = null;
      renderPending();
      log(`已写入 EXP：${pending.python}`);
    });
    $('#pending-simulate').addEventListener('click', async () => {
      try {
        const result = await window.pwnbao.request('heap_apply_pending', {
          step: pending.step, canonical: pending.canonical, python: pending.python,
        });
        absorbState(result, 'CANVAS→IR');
        state.pendingStep = null;
        renderPending();
        log(`已作为 Canonical Operation 推演：${result.appended_operation?.title || ''}`);
      } catch (error) {
        log(`推演失败：${error.message}`, 'error');
      }
    });
    $('#pending-discard').addEventListener('click', () => {
      state.pendingStep = null;
      renderPending();
    });
  }

  async function solvePendingFromPatch(step, patch) {
    try {
      const result = await window.pwnbao.request('heap_reverse_edit', {
        step, address: patch.address,
        data_hex: patch.data_hex || '',
        length: patch.length || 8,
      });
      state.pendingStep = {
        step,
        canonical: result.canonical,
        python: result.python,
        effectsText: (result.effects || [])
          .map((effect) => `写入 ${effect.chunk}.${effect.field} [${effect.start} ~ ${effect.end})`)
          .join('；') + (result.source && result.source.overflow ? ' · 溢出写入' : ''),
        alternatives: result.alternatives || [],
      };
      renderPending();
      log(`反向求解成功：${result.python}`);
    } catch (error) {
      state.pendingStep = null;
      renderPending();
      log(`反向求解不可用：${error.message}`, 'warn');
    }
  }

  /**
   * 步骤上下文的唯一出口是 Logs/Diagnostics（不再有画布角落步骤卡/i 按钮）：
   *   warning/abort 永远记录；解释只在 verbose（用户跳步/显式提交）时记录，
   *   避免 EXP 实时回放每个键入都刷屏。
   */
  function logStepContext(verbose) {
    const step = state.steps[state.current];
    if (!step) return;
    const tag = `#${String(step.step).padStart(2, '0')}`;
    for (const warning of step.warnings || []) {
      const severe = ['error', 'fatal'].includes(String(warning.severity).toLowerCase());
      log(`${tag} ⚠ [${warning.severity}] ${warning.title}：${warning.message}`, severe ? 'error' : 'warn');
    }
    if (step.aborted) log(`${tag} ⛔ allocator 已终止：严格模式不再伪造后续状态。`, 'error');
    if (verbose) {
      for (const line of step.explanation || []) log(`${tag} ${line}`, 'info');
    }
  }

  // =====================================================================
  // Canvas rendering + interaction

  let viewDpr = 1;
  let cssW = 300;
  let cssH = 300;

  /** 内容边界缓存：滚轮/悬停不改变 chunk 几何，O(n) 扫描只在几何变化后发生。 */
  function invalidateHeapBounds() {
    heapBoundsCache.valid = false;
  }

  function heapContentBounds() {
    if (!heapBoundsCache.valid) {
      let top = 0;
      let bottom = 0;
      for (const body of world.bodies) {
        if (!body.data || body.data.kind !== 'chunk') continue;
        if (!bottom) top = body.y;
        top = Math.min(top, body.y);
        bottom = Math.max(bottom, body.y + body.h);
      }
      heapBoundsCache.top = top;
      heapBoundsCache.bottom = bottom;
      heapBoundsCache.valid = true;
    }
    // bins 在独立右栏画布，不再参与 chunk 画布的内容边界。
    // 返回共享缓存对象：调用方只读，不得改写。
    return heapBoundsCache;
  }

  function clampVerticalScroll(nextY) {
    const bounds = heapContentBounds();
    if (!bounds.bottom) return 0;
    const minY = Math.min(0, cssH - bounds.bottom - 70);
    return Math.max(minY, Math.min(0, Number(nextY) || 0));
  }

  function resizeCanvas() {
    if (!canvas || !canvasHost) return;
    // 按 devicePixelRatio 放大 backing store，否则高分屏（125%/150% 缩放）下模糊
    viewDpr = Math.max(1, window.devicePixelRatio || 1);
    const rect = canvasHost.getBoundingClientRect();
    cssW = Math.max(200, Math.floor(rect.width));
    cssH = Math.max(200, Math.floor(rect.height));
    canvas.width = Math.floor(cssW * viewDpr);
    canvas.height = Math.floor(cssH * viewDpr);
    canvas.style.width = `${cssW}px`;
    canvas.style.height = `${cssH}px`;
    state.camera.scale = 1;
    state.camera.x = 0;
    state.camera.y = clampVerticalScroll(state.camera.y);
    needsDraw = true;
  }

  function resizeBinsCanvas() {
    if (!binsCanvas || !binsHost) return;
    binsDpr = Math.max(1, window.devicePixelRatio || 1);
    const rect = binsHost.getBoundingClientRect();
    binsCssW = Math.max(160, Math.floor(rect.width));
    binsCssH = Math.max(160, Math.floor(rect.height));
    binsCanvas.width = Math.floor(binsCssW * binsDpr);
    binsCanvas.height = Math.floor(binsCssH * binsDpr);
    binsCamera.y = clampBinsScroll(binsCamera.y);
    binsNeedsDraw = true;
  }

  function tick() {
    try {
      // 滚轮合帧：一帧内任意多个 wheel 事件只消费一次累计 delta。
      // 跟手优先：不做惯性平滑，最多引入一帧延迟。
      if (pendingWheelDelta !== 0) {
        const delta = pendingWheelDelta;
        pendingWheelDelta = 0;
        const nextY = clampVerticalScroll(state.camera.y - delta);
        if (nextY !== state.camera.y) {
          state.camera.y = nextY;
          needsDraw = true;
        }
        // draft 行是 DOM 覆盖层，跟画布滚动对齐合并到同一帧
        if (state.draftRow) positionDraftRow();
      }
      // 确定性布局：没有物理步进。只有 needsDraw（加载/拖动/悬停/滚动）时重绘。
      if (needsDraw) {
        draw();
        needsDraw = false;
      }
      if (binsNeedsDraw) {
        drawBins();
        binsNeedsDraw = false;
      }
    } catch (error) {
      console.error('[heap draw]', error);
      log(`画布渲染异常：${error.message}`, 'error');
    }
    requestAnimationFrame(tick);
  }

  /** 拖动时的吸附辅助线（水平虚线，屏幕坐标 = 世界 y + camera.y）。 */
  function drawGuides() {
    if (!state.guides || !state.guides.length) return;
    ctx.save();
    ctx.strokeStyle = 'rgba(0, 120, 212, 0.65)';
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 4]);
    for (const gy of state.guides) {
      const screenY = gy + state.camera.y;
      ctx.beginPath();
      ctx.moveTo(0, screenY + 0.5);
      ctx.lineTo(canvas.clientWidth, screenY + 0.5);
      ctx.stroke();
    }
    ctx.restore();
  }

  // =====================================================================
  // RendererPlan 导出（INFRA-CLOSURE-1 P0-5）
  // 必须复用真实几何管线（chunkLayout / chunkSizeTriple / cachedChunkGrid /
  // coverageSpansFor / bodiesByChunk / allBinLayouts），禁止在此重算或近似。

  function exportRendererPlan(step) {
    const layout = chunkLayout(step);
    const cards = [];
    for (const entry of layout) {
      const chunk = entry.chunk;
      const triple = chunkSizeTriple(chunk);
      const grid = cachedChunkGrid(chunk, step, state.editMode);
      const key = chunkBodyKey(chunk);
      const body = bodiesByChunk.get(key) || null;
      cards.push({
        physical_id: chunk.physical_id || '',
        chunk_id: chunk.chunk_id || '',
        offset: entry.offset,
        size: entry.size,
        geometry: body ? { x: body.x, y: body.y, w: body.w, h: body.h } : null,
        geometry_basis: 'physical_extent_size',
        size_triple: {
          header_raw_size: String(triple.headerRawSize),
          decoded_chunksize: String(triple.decodedChunkSize ?? ''),
          physical_extent_size: String(triple.physicalExtentSize ?? ''),
        },
        grid_height: grid.height,
        word: grid.word,
        user_row_bytes: grid.userRowBytes,
        row_count: grid.rows.length,
        rows: grid.rows.map((row) => ({
          kind: row.kind, name: row.name || '', off: row.off,
          bytes: row.bytes || 0, full: !!row.full,
          // cell byte ranges as drawCell sees them: word-wide halves of the
          // row span derived from the SAME grid object (no reimplementation)
          cells: row.kind === 'marker'
            ? []
            : [0, 1]
                .map((k) => ({ start: row.off + k * grid.word,
                               end: Math.min(row.off + row.bytes || row.off + grid.word * 2,
                                             row.off + (k + 1) * grid.word) }))
                .filter((cell) => cell.end > cell.start),
        })),
        truncated: !!grid.truncated,
        virtualized: !!grid.truncated,
        virtualization_regime: state.editMode
          ? 'collapsed: maxVisibleUserRows=6 + head/tail 2 + covered rows'
          : 'rowLimit=4096',
        spans: {
          cross: (grid.spans.cross || []).map((sp) => ({ start: sp.start, end: sp.end })),
          overlap: (grid.spans.overlap || []).map((sp) => ({ start: sp.start, end: sp.end })),
        },
        covered_byte_range: [0, grid.size],
      });
    }
    const topBody = bodiesByChunk.get('__top__') || null;
    let binsLayout = null;
    try { binsLayout = allBinLayouts(step); } catch (err) { binsLayout = null; }
    return {
      step: step.step,
      op_id: step.op_id || step.operation_id || '',
      snapshot_id: state.snapshotId,
      memory_revision: state.memoryRevision,
      edit_mode: !!state.editMode,
      cards,
      top_card: topBody
        ? { x: topBody.x, y: topBody.y, w: topBody.w, h: topBody.h,
            chunk: topBody.data && topBody.data.chunk
              ? { chunk_id: topBody.data.chunk.chunk_id, view_kind: 'top_chunk',
                  chunk_size: String(topBody.data.chunk.chunk_size || '') }
              : null }
        : null,
      bins_layout: binsLayout,
    };
  }

  function rebuildAndPlan(steps, current) {
    state.steps = steps;
    state.current = Math.max(0, Math.min(current, steps.length - 1));
    rebuildWorld();
    return exportRendererPlan(state.steps[state.current]);
  }

  function draw() {
    if (!ctx) return;
    const step = state.steps[state.current];
    ctx.setTransform(viewDpr, 0, 0, viewDpr, 0, 0);
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, cssW, cssH);
    // 辅助线必须画在背景之后 —— 之前先画线再铺背景，线永远被盖住
    drawGuides();
    if (!step) {
      ctx.fillStyle = COLORS.dim;
      ctx.font = '13px "Cascadia Mono", Consolas, monospace';
      // y=24：顶部不再画状态行，直接从画布左上角开始
      ctx.fillText('exp 中暂未识别到堆构造操作 —— 在左边写 add/free/edit/show 即可实时上屏', 24, 24);
      return;
    }
    const empty = $('#heap-empty');
    if (empty) empty.hidden = true;
    ctx.setTransform(
      viewDpr, 0, 0, viewDpr,
      viewDpr * state.camera.x, viewDpr * state.camera.y,
    );

    // chunk grids (fixed cells + coverage paint)
    // viewport culling：纯 Renderer 优化 —— world/snapshot/物理排序一个不动，
    // 只是视口上下 100px 之外的卡不画。命中测试/编辑/回放仍作用于完整模型。
    const viewportTop = -state.camera.y;
    const viewportBottom = viewportTop + cssH;
    const cullMargin = 100;
    const viewport = { top: viewportTop - cullMargin, bottom: viewportBottom + cullMargin };
    for (const body of world.bodies) {
      const chunk = body.data && body.data.chunk;
      if (!chunk) continue;
      if (body.y + body.h < viewportTop - cullMargin || body.y > viewportBottom + cullMargin) continue;
      drawChunkGrid(body, chunk, step, viewport);
    }

    // 边界拖动实时预览：按物理区间 ∩ 相邻 chunk 计算（与正式 paint_spans
    // 同一区间逻辑）。红 = 真实进入对方物理范围的 cell；蓝 = 本 chunk 新
    // 占用的区域；灰 = 收缩后脱离本 chunk 视图的字节。松手才提交事务。
    if (state.resizePreview && state.resizePreview.bands) {
      const colors = {
        overlap: ['rgba(229, 85, 79, 0.32)', 'rgba(229, 85, 79, 0.85)'],
        grow: ['rgba(91, 141, 239, 0.22)', 'rgba(91, 141, 239, 0.7)'],
        shrink: ['rgba(200, 202, 208, 0.10)', 'rgba(200, 202, 208, 0.4)'],
      };
      for (const band of state.resizePreview.bands) {
        const [fill, stroke] = colors[band.kind] || colors.shrink;
        const y0 = Math.min(band.y0, band.y1);
        const y1 = Math.max(band.y0, band.y1);
        ctx.save();
        ctx.fillStyle = fill;
        ctx.strokeStyle = stroke;
        ctx.lineWidth = 1;
        const px = band.x - 2;
        const pw = band.w + 4;
        ctx.fillRect(px, y0, pw, y1 - y0);
        ctx.strokeRect(px + 0.5, y0 + 0.5, pw - 1, y1 - y0 - 1);
        ctx.restore();
      }
    }
  }

  const CHUNK_PALETTE = ['#5b8def', '#4fae9b', '#c96fb6', '#d0a23a', '#6fc3df', '#a8c05b', '#e07b54', '#b58ee0', '#7f9f4a', '#d9646f'];
  function chunkIdentityColor(chunk) {
    // 每 chunk 一个稳定身份色：按 physical_id 哈希取色，与数组下标无关 ——
    // chunk 重排/邻居释放后同一物理块颜色不变（按 index 取色会随重排变色）。
    const key = chunkBodyKey(chunk);
    let hash = 2166136261;
    for (let index = 0; index < key.length; index += 1) {
      hash ^= key.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return CHUNK_PALETTE[Math.abs(hash) % CHUNK_PALETTE.length];
  }

  // freed 统一灰色（用户口径：被释放的 chunk 一眼可辨）；fake/TOP 保留语义色
  function lifecycleColor(chunk) {
    if (chunk.view_kind === 'fake_chunk') return COLORS.fake;
    if (chunk.lifecycle === 'top') return COLORS.top;
    if (chunk.lifecycle === 'freed') return '#7a7a82';
    return chunkIdentityColor(chunk);
  }

  function binLabel(chunk) {
    const raw = String(chunk.bin_location || '').trim();
    if (!raw || raw === 'allocated' || raw === 'top') return '';
    return raw;
  }

  /**
   * reuse 解释标签（纯展示）：标题里的「当前逻辑身份 ← 原物理身份来源」。
   * 数据来自后端整包快照——同一 physical_id 的历次 generation
   * （allocation_instances，按创建顺序）；减去当前逻辑身份后，剩下的就是
   * 这块物理内存曾经的身份。单次复用 → "← reuse B"；多次 → "← reuse B→F"。
   * 只是可读性增强：绝不参与排序、命中测试、字段溯源、结构编辑、回放或 bins。
   */
  function reuseSourceLabel(chunk) {
    if (!chunk || chunk.view_kind === 'top_chunk' || chunk.view_kind === 'fake_chunk') return '';
    const currentId = String(chunk.chunk_id || '');
    let history = [];
    if (Array.isArray(chunk.allocation_instances) && chunk.allocation_instances.length > 1) {
      history = chunk.allocation_instances.map((item) => String((item && item.chunk_id) || ''));
    } else if (Array.isArray(chunk.aliases)) {
      history = chunk.aliases.map((id) => String(id || ''));
    }
    const seen = new Set([currentId]);
    const prior = [];
    for (const id of history) {
      if (!id || seen.has(id)) continue;
      seen.add(id);
      prior.push(id);
    }
    return prior.length ? `← reuse ${prior.join('→')}` : '';
  }

  function structurallyEditableChunk(chunk) {
    if (!state.editMode || !chunk) return false;
    return chunk.view_kind !== 'top_chunk' && chunk.view_kind !== 'fake_chunk'
      && chunk.lifecycle !== 'top';
  }

  /** 行右下角常驻小圆形 ⊕：在任意行之后插入真实物理行（≠ 顶/底边 ●）。 */
  function drawRowInsertControl(body, chunk, rowTopY, rowH, rowKey) {
    if (!structurallyEditableChunk(chunk)) return;
    const cx = body.x + GRID.cardW - 13;
    const cy = rowTopY + rowH / 2;
    const hovered = state.hoveredRowInsert === `${chunkBodyKey(chunk)}:${rowKey}`
      || (state.draftRow && state.draftRow.rowKey === rowKey
        && chunkBodyKey(state.draftRow.chunk) === chunkBodyKey(chunk));
    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, 6.5, 0, Math.PI * 2);
    ctx.fillStyle = hovered ? '#168bd2' : COLORS.bg;
    ctx.strokeStyle = hovered ? '#70c7ff' : 'rgba(200, 202, 208, 0.6)';
    ctx.lineWidth = 1;
    ctx.fill();
    ctx.stroke();
    ctx.strokeStyle = hovered ? '#ffffff' : 'rgba(200, 202, 208, 0.85)';
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    ctx.moveTo(cx - 2.8, cy);
    ctx.lineTo(cx + 2.8, cy);
    ctx.moveTo(cx, cy - 2.8);
    ctx.lineTo(cx, cy + 2.8);
    ctx.stroke();
    ctx.restore();
  }

  /**
   * 顶/底边中央圆形 resize handle（●）：拖动 = 改变真实物理边界
   *（physical_start/extent），侵入相邻 chunk 即真实 overlap。
   * 首个 chunk 顶边锁定：画灰点占位，不参与命中。
   */
  function drawResizeHandles(body, chunk, step) {
    if (!structurallyEditableChunk(chunk)) return;
    const lockTop = isFirstPhysicalChunk(chunk, step);
    const cx = body.x + body.w / 2;
    for (const edge of ['top', 'bottom']) {
      const locked = edge === 'top' && lockTop;
      if (edge === 'top' && lockTop) {
        const cy = body.y;
        ctx.save();
        ctx.globalAlpha = 0.28;
        ctx.beginPath();
        ctx.arc(cx, cy, RESIZE_HANDLE_RADIUS - 2, 0, Math.PI * 2);
        ctx.fillStyle = COLORS.bg;
        ctx.strokeStyle = 'rgba(200, 202, 208, 0.7)';
        ctx.lineWidth = 1;
        ctx.fill();
        ctx.stroke();
        ctx.restore();
        continue;
      }
      const cy = edge === 'top' ? body.y : body.y + body.h;
      const hovered = state.hoveredResize === `${chunkBodyKey(chunk)}:${edge}`;
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, RESIZE_HANDLE_RADIUS, 0, Math.PI * 2);
      ctx.fillStyle = hovered ? '#168bd2' : COLORS.bg;
      ctx.strokeStyle = hovered ? '#70c7ff' : 'rgba(200, 202, 208, 0.9)';
      ctx.lineWidth = 1.3;
      ctx.fill();
      ctx.stroke();
      // 纵向拉伸提示：上下小箭头刻度
      ctx.strokeStyle = hovered ? '#ffffff' : 'rgba(200, 202, 208, 0.9)';
      ctx.lineWidth = 1.1;
      ctx.beginPath();
      ctx.moveTo(cx - 3, cy - 1.5);
      ctx.lineTo(cx, cy - 3.5);
      ctx.lineTo(cx + 3, cy - 1.5);
      ctx.moveTo(cx - 3, cy + 1.5);
      ctx.lineTo(cx, cy + 3.5);
      ctx.lineTo(cx + 3, cy + 1.5);
      ctx.stroke();
      ctx.restore();
    }
  }

  function drawHeaderBadge(text, x, y, fill, stroke) {
    if (!text) return;
    ctx.save();
    ctx.font = 'bold 9px "Cascadia Mono", Consolas, monospace';
    const padX = 5;
    const bw = ctx.measureText(text).width + padX * 2;
    const bx = x - bw;
    ctx.fillStyle = fill || 'rgba(215, 140, 69, 0.22)';
    ctx.strokeStyle = stroke || 'rgba(215, 140, 69, 0.85)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(bx, y, bw, 12, 3);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = '#ffd7a0';
    ctx.fillText(text, bx + padX, y + 9);
    ctx.restore();
  }

  /** freed 徽标：实底红 + 白字 + 微光，确保一眼可辨（右上角）。 */
  function drawFreedBadge(x, y) {
    const text = 'FREED';
    ctx.save();
    ctx.font = 'bold 10px "Cascadia Mono", Consolas, monospace';
    const padX = 7;
    const bw = ctx.measureText(text).width + padX * 2;
    const bh = 16;
    const bx = x - bw;
    const by = y;
    ctx.shadowColor = 'rgba(248, 81, 73, 0.9)';
    ctx.shadowBlur = 7;
    ctx.fillStyle = '#e5484d';
    ctx.beginPath();
    ctx.roundRect(bx, by, bw, bh, 4);
    ctx.fill();
    ctx.shadowBlur = 0;
    ctx.strokeStyle = '#ffe1e0';
    ctx.lineWidth = 1.2;
    ctx.stroke();
    ctx.fillStyle = '#ffffff';
    ctx.fillText(text, bx + padX, by + 12);
    ctx.restore();
  }

  function drawChunkGrid(body, chunk, step, viewport) {
    const grid = cachedChunkGrid(chunk, step, state.editMode);
    const x = body.x;
    const y = body.y;
    const w = GRID.cardW;
    const accent = lifecycleColor(chunk);
    const cellW = w / 2;   // 两格精确占满整宽，右缘与色带/边框严格对齐

    // 每个 chunk 顶部一条身份色带：左边是 chunk 名称；free 状态只在同一行右侧打 freed 标识。
    ctx.fillStyle = accent;
    ctx.fillRect(x, y, w, GRID.titleH);
    ctx.fillStyle = '#101014';
    ctx.font = 'bold 11px "Cascadia Mono", Consolas, monospace';
    const menuInline = chunk.menu_indexes && chunk.menu_indexes.length ? ` [${chunk.menu_indexes.join(',')}]` : '';
    const titleBaseline = y + Math.min(13, GRID.titleH - 5);
    const titleText = `${chunk.chunk_id}${menuInline}`;
    ctx.fillText(titleText, x + 8, titleBaseline);
    // 复用解释标签：O [14] ← reuse B（同一物理块的曾用名，纯展示）
    const reuseLabel = reuseSourceLabel(chunk);
    if (reuseLabel) {
      const suffixFont = '9px "Cascadia Mono", Consolas, monospace';
      const mainW = ctx.measureText(titleText).width;
      // freed 卡右侧要给 FREED 徽标让位
      const reserved = chunk.lifecycle === 'freed' ? 64 : 12;
      ctx.font = suffixFont;
      ctx.fillStyle = 'rgba(16, 16, 20, 0.75)';
      ctx.fillText(fitText(reuseLabel, Math.max(24, w - 8 - mainW - 6 - reserved), suffixFont), x + 8 + mainW + 6, titleBaseline);
    }
    if (chunk.lifecycle === 'freed') drawFreedBadge(x + w - 8, y + 1);
    let cy = y + GRID.titleH;
    ctx.lineWidth = 1;

    // 先画格子，再画左侧地址信息 —— 地址标签永远不会被模型遮挡
    const gutterLabels = [];
    // 行级渲染虚拟化（编辑模式全量行时必须）：只画视口内的行，
    // 绝不把真实行合并成 marker —— 语义永远完整。
    const viewTop = viewport ? viewport.top : -Infinity;
    const viewBottom = viewport ? viewport.bottom : Infinity;

    for (const row of grid.rows) {
      const rowH = row.kind === 'marker' ? GRID.markerH : GRID.rowH;
      const rowVisible = cy + rowH >= viewTop && cy <= viewBottom;
      if (!rowVisible) {
        cy += rowH;
        continue;
      }
      if (row.kind === 'marker') {
        ctx.fillStyle = '#0e0e10';
        ctx.fillRect(x, cy, w, GRID.markerH);
        ctx.strokeStyle = COLORS.cardBorder;
        ctx.strokeRect(x + 0.5, cy + 0.5, w - 1, GRID.markerH - 1);
        ctx.fillStyle = COLORS.dim;
        ctx.font = '9.5px "Cascadia Mono", Consolas, monospace';
        const markerText = grid.truncated
          ? `⋯ size 超出可渲染范围，已折叠显示 ⋯`
          : `⋯ 0x${row.bytes.toString(16)} 字节未触及，已虚拟化 ⋯`;
        ctx.fillText(markerText, x + 10, cy + 12);
        cy += GRID.markerH;
        continue;
      }
      const offText = `+0x${row.off.toString(16).padStart(2, '0')}`;
      const labelText = row.kind === 'header' ? `${offText} header` : `${offText} user`;
      const labelY = cy + GRID.rowH / 2 + 3;
      // header（prev_size|size）与 user 行同为两格 16 字节行 —— 全表右缘对齐
      const rowKey = row.kind === 'header' ? 'hdr' : `u${row.index}`;
      for (let half = 0; half < 2; half += 1) {
        const start = grid.base !== null ? grid.base + row.off + half * grid.word : null;
        drawCell(x + half * cellW, cy, cellW, start, start !== null ? start + grid.word : null, chunk, grid, row, half, accent);
      }
      // 行右下角 ⊕：在该行之后插入真实物理行（与顶/底边 ● 是不同操作）
      drawRowInsertControl(body, chunk, cy, GRID.rowH, rowKey);
      gutterLabels.push([labelText, labelY]);
      cy += GRID.rowH;
    }

    // 地址 gutter：全部右对齐到模型左侧外沿；chunk 地址放在头部色带同一行，不再漂在两块之间。
    ctx.font = '10px "Cascadia Mono", Consolas, monospace';
    ctx.textAlign = 'right';
    const chunkAddrText = chunk.heap_offset ? formatOffset(parseAddr(chunk.heap_offset)) : relAddr(chunk.address, grid.base);
    ctx.fillStyle = chunkIdentityColor(chunk);
    ctx.fillText(`─ ${chunkAddrText}`, x - 10, y + Math.min(13, GRID.titleH - 5));
    for (const [text, labelY] of gutterLabels) {
      ctx.fillStyle = COLORS.dim;
      ctx.fillText(text, x - 10, labelY);
    }
    ctx.textAlign = 'left';

    // 右侧只放结构信息：物理范围与 size 字段严格分列（尺寸三拆）；
    // chunk 名称/生命周期留在头部行，避免重复和错位。
    ctx.font = '9.5px "Cascadia Mono", Consolas, monospace';
    const triple = chunkSizeTriple(chunk);
    ctx.fillStyle = COLORS.dim;
    ctx.fillText(`物理 ${triple.physicalExtentSize !== null ? `0x${triple.physicalExtentSize.toString(16)}` : '?'}`.slice(0, 56), x + w + 10, y + 12);
    // header_raw（含 flags）与物理 extent 不一致 = size 字段被改/被写坏 → 高亮提示
    const sizeDiverged = triple.decodedChunkSize !== null && triple.physicalExtentBig !== null
      && triple.decodedChunkSize !== triple.physicalExtentBig;
    ctx.fillStyle = sizeDiverged ? COLORS.freed : COLORS.dim;
    ctx.fillText(`size字段 ${triple.headerRawSize || chunk.chunk_size}`.slice(0, 64), x + w + 10, y + 24);
    const bin = binLabel(chunk);
    if (bin) {
      ctx.fillStyle = chunk.lifecycle === 'freed' ? COLORS.freed : COLORS.dim;
      ctx.fillText(`bin ${bin}`.slice(0, 56), x + w + 10, y + 36);
    }

    // 左沿 accent 条（2px，不占行高）
    ctx.fillStyle = accent;
    ctx.fillRect(x - 2, y, 2, cy - y);

    if (state.selectedPhysicalId === chunkBodyKey(chunk)) {
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1.5;
      ctx.strokeRect(x - 1.5, y - 0.5, w + 3, cy - y + 1);
    }
    if (chunk.evidence_level) {
      ctx.fillStyle = COLORS.fake;
      ctx.font = '9px "Cascadia Mono", Consolas, monospace';
      ctx.fillText(`证据: ${chunk.evidence_level}`, x + w + 10, y + 48);
    }
    // 顶/底边中央圆形 resize handle（编辑模式）：拖动改变真实物理边界
    drawResizeHandles(body, chunk, step);
  }

  function fitText(text, maxWidth, font, g = ctx) {
    // 零裁字：先逐级降字号让全文放下；字号到底仍放不下才允许省略号
    text = String(text);
    g.font = font;
    if (g.measureText(text).width <= maxWidth) return text;
    const sizeMatch = /([\d.]+)px/.exec(font);
    if (sizeMatch) {
      const base = parseFloat(sizeMatch[1]);
      for (let size = Math.round((base - 0.5) * 2) / 2; size >= 6.5; size -= 0.5) {
        g.font = font.replace(sizeMatch[0], `${size}px`);
        if (g.measureText(text).width <= maxWidth) return text;
      }
      g.font = font.replace(sizeMatch[0], '6.5px');
    }
    let clipped = text;
    while (clipped.length > 1 && g.measureText(clipped + '…').width > maxWidth) {
      clipped = clipped.slice(0, -1);
    }
    return clipped + '…';
  }

  function drawCell(cx, cy, cw, start, end, chunk, grid, row, half, accent) {
    // extent 非整行时的 partial row：多出的 cell 没有物理字节，诚实画成越界
    //（header 行 userRel 为负，永不越界）
    const userRel = row.off - grid.word * 2 + half * grid.word;
    if (userRel >= grid.userBytes) {
      ctx.fillStyle = '#131316';
      ctx.fillRect(cx, cy, cw, GRID.rowH);
      ctx.save();
      ctx.setLineDash([3, 3]);
      ctx.strokeStyle = 'rgba(200, 202, 208, 0.28)';
      ctx.strokeRect(cx + 0.5, cy + 0.5, cw - 1, GRID.rowH - 1);
      ctx.restore();
      ctx.fillStyle = '#5a5a62';
      ctx.font = '9px "Cascadia Mono", Consolas, monospace';
      ctx.fillText('beyond extent', cx + 6, cy + 12);
      return;
    }
    // flush square cell — 同一 chunk 从头部到尾部用同一个身份色背景
    ctx.fillStyle = row.kind === 'header' ? '#1d1d22' : '#1f1f24';
    ctx.fillRect(cx, cy, cw, GRID.rowH);
    ctx.fillStyle = accent || COLORS.card;
    ctx.globalAlpha = row.kind === 'header' ? 0.22 : 0.13;
    ctx.fillRect(cx, cy, cw, GRID.rowH);
    ctx.globalAlpha = 1;
    ctx.strokeStyle = COLORS.cardBorder;
    ctx.strokeRect(cx + 0.5, cy + 0.5, cw - 1, GRID.rowH - 1);

    const value = cellValue(chunk, grid, start, half);
    const valueFont = '10.5px "Cascadia Mono", Consolas, monospace';
    ctx.font = valueFont;
    ctx.fillStyle = value.provenance === 'observed' ? '#e8c268'
      : value.provenance === 'unknown' ? '#707078' : COLORS.text;
    const raw = value.value === 'unknown' ? '——' : String(value.value);
    const label = fitText(raw, cw - 12, valueFont);
    ctx.fillText(label, cx + 6, cy + 12);
    ctx.font = '9px "Cascadia Mono", Consolas, monospace';
    ctx.fillStyle = COLORS.dim;
    // 格子内只写 chunk 内相对偏移：+0x0/+0x8/+0x10/+0x18……
    // heap 大偏移只在 chunk 头部 gutter 显示，不在每格重复一段范围。
    const relativeInChunk = start !== null && grid.base !== null ? start - grid.base : null;
    const sub = relativeInChunk !== null ? formatOffset(relativeInChunk) : `${grid.word} bytes`;
    ctx.fillText(fitText(sub, cw - 12, '9px "Cascadia Mono", Consolas, monospace'), cx + 6, cy + 23);

    // CoverageSpan ∩ Cell → paint INSIDE the fixed cell, never new rows.
    // cross（红/正斜线）与 overlap（紫/反斜线）是两种语义，纹理分开。
    if (start !== null && end !== null) {
      const paint = (parts, color, reverse) => {
        for (const [a, b] of parts) {
          const px = cx + ((a - start) / (end - start)) * cw;
          const pw = Math.max(2, ((b - a) / (end - start)) * cw);
          ctx.save();
          ctx.beginPath();
          ctx.rect(px, cy, pw, GRID.rowH);
          ctx.clip();
          ctx.fillStyle = color;
          ctx.globalAlpha = 0.22;
          ctx.fillRect(px, cy, pw, GRID.rowH);
          ctx.globalAlpha = 1;
          ctx.strokeStyle = color;
          ctx.globalAlpha = 0.85;
          ctx.lineWidth = 1;
          for (let hx = -GRID.rowH; hx < pw; hx += 5) {
            ctx.beginPath();
            if (reverse) {
              ctx.moveTo(px + hx, cy);
              ctx.lineTo(px + hx + GRID.rowH, cy + GRID.rowH);
            } else {
              ctx.moveTo(px + hx, cy + GRID.rowH);
              ctx.lineTo(px + hx + GRID.rowH, cy);
            }
            ctx.stroke();
          }
          ctx.globalAlpha = 1;
          ctx.restore();
        }
      };
      paint(coveredSubRanges(start, end, grid.spans.cross), COLORS.crossWrite, false);
      paint(coveredSubRanges(start, end, grid.spans.overlap), COLORS.overlap, true);
    }

    // 编辑模式：单元格选中高亮（点击选中 → 再点同一格编辑真实值）
    if (state.selectedCell
      && state.selectedCell.bodyKey === chunkBodyKey(chunk)
      && state.selectedCell.off === row.off
      && state.selectedCell.half === half) {
      ctx.save();
      ctx.strokeStyle = '#ffd7a0';
      ctx.lineWidth = 1.6;
      ctx.strokeRect(cx + 1, cy + 1, cw - 2, GRID.rowH - 2);
      ctx.globalAlpha = 0.08;
      ctx.fillStyle = '#ffd7a0';
      ctx.fillRect(cx + 1, cy + 1, cw - 2, GRID.rowH - 2);
      ctx.restore();
    }
  }

  // ===================================================================
  // Explicit bin chains
  //
  // snapshot.bins 才是 bin 顺序的真值。不把链条猜成 chunk 在 heap
  // 列中的几何顺序，而是对每个 size class 画一条独立链。bin 图整体
  // 放在 chunk 右列更远的位置（+200px），避免遮挡 chunk 右缘文字。

  const BIN_VIEW = {
    groupGap: 18,
    titleH: 27,
    singleW: 92,
    singleH: 36,
    doubleW: 116,
    doubleH: 40,
    nodeGap: 34,
    rowGap: 34,
    // unsorted count=1 三格两端的紧凑 arena 方块与间距：面板回到 320px
    // 后「arena ↔ 单节点 ↔ arena」仍要一行放下（58+20+116+20+58=272）。
    endW: 58,
    endGap: 20,
  };

  function binDiagramStartX() {
    return 12;   // bins 面板自己的坐标系：不再借用 chunk 画布的 laneX 偏移
  }

  function binChainGroups(step) {
    const bins = (step && step.bins) || {};
    const groups = [];
    const addSized = (source, kind, color, doubly = false) => {
      const entries = Object.entries(source || {}).sort((a, b) => {
        const av = parseAddr(a[0]);
        const bv = parseAddr(b[0]);
        if (av !== null && bv !== null) return av - bv;
        return String(a[0]).localeCompare(String(b[0]));
      });
      for (const [size, chain] of entries) {
        if (!Array.isArray(chain) || !chain.length) continue;
        groups.push({ kind, label: `${kind}[${size}]`, size, chain, color, doubly });
      }
    };
    addSized(bins.tcache, 'tcache', COLORS.tcache, false);
    addSized(bins.fastbins, 'fastbin', COLORS.fastbin, false);
    if (Array.isArray(bins.unsorted) && bins.unsorted.length) {
      groups.push({ kind: 'unsorted', label: 'unsorted bin', size: '', chain: bins.unsorted, color: COLORS.unsorted, doubly: true });
    }
    addSized(bins.smallbins, 'smallbin', COLORS.smallbins, true);
    addSized(bins.largebins, 'largebin', COLORS.largebins, true);
    return groups;
  }

  function binGroupLayout(group, y) {
    const startX = binDiagramStartX();
    const nodeW = group.doubly ? BIN_VIEW.doubleW : BIN_VIEW.singleW;
    const nodeH = group.doubly ? BIN_VIEW.doubleH : BIN_VIEW.singleH;
    // 双链表是「以 arena 为哨兵的循环双链」。unsorted 只有 1 个 chunk 时，
    // 该 chunk 的 fd 和 bk 都指向 arena（main_arena 的 bin 头），画成
    // 「arena ↔ 单节点 ↔ arena」三个方块；其余双链只画一个 arena 哨兵 +
    // 回环弧闭合。单链表显示 bin head 和 NULL。
    const available = Math.max(nodeW * 2 + BIN_VIEW.nodeGap, binsCssW - binDiagramStartX() - 24);
    // 三格候选：紧凑 arena + 单节点 + 紧凑 arena；面板太窄放不下时不硬折行，
    // 退回「单 arena 哨兵 + 回环弧」的画法。
    const trioW = BIN_VIEW.endW + BIN_VIEW.endGap + nodeW + BIN_VIEW.endGap + BIN_VIEW.endW;
    const arenaBookends = group.doubly && group.kind === 'unsorted'
      && group.chain.length === 1 && trioW <= available;
    const sequenceLength = group.doubly
      ? group.chain.length + (arenaBookends ? 2 : 1)
      : group.chain.length + 2;
    const perRow = arenaBookends ? 3 : Math.max(2, Math.floor((available + BIN_VIEW.nodeGap) / (nodeW + BIN_VIEW.nodeGap)));
    const rows = Math.max(1, Math.ceil(sequenceLength / perRow));
    // 双链的回环弧（fd/bk 闭合环）在节点上下各伸出 ~46px：顶部内边距让弧
    // 从标题与节点之间穿过，底部预留空间，避免压到标题或下一组。
    const topPad = group.doubly ? 24 : 0;
    const arcPad = group.doubly ? 34 : 0;
    const height = BIN_VIEW.titleH + topPad + rows * nodeH + (rows - 1) * BIN_VIEW.rowGap + 12 + arcPad;
    return {
      ...group, x: startX, y, nodeW, nodeH, perRow, rows, height, topPad,
      arenaBookends, endW: BIN_VIEW.endW, endGap: BIN_VIEW.endGap,
    };
  }

  function allBinLayouts(step) {
    let y = 6;
    return binChainGroups(step).map((group) => {
      const layout = binGroupLayout(group, y);
      y += layout.height + BIN_VIEW.groupGap;
      return layout;
    });
  }

  function binDiagramBottom(step) {
    const layouts = allBinLayouts(step);
    if (!layouts.length) return 0;
    const last = layouts[layouts.length - 1];
    return last.y + last.height + 18;
  }

  function binNodeTruth(nodeId, step) {
    const id = String(nodeId ?? '');
    const chunk = stepChunks(step).find((item) => String(item.physical_id) === id)
      || stepChunks(step).find((item) => String(item.chunk_id) === id)
      || ((step && step.typed_views) || []).find((item) => String(item.chunk_id) === id);
    if (!chunk) return { label: id || '?', address: '' };
    const offset = displayOffsetForChunk(chunk, step, null);
    return {
      label: String(chunk.chunk_id || id),
      address: offset === null ? relAddr(chunk.address || '') : formatOffset(offset),
    };
  }
  function chainNodePosition(layout, index) {
    if (layout.arenaBookends) {
      // 「arena ↔ 单节点 ↔ arena」：两端是紧凑 arena 方块（endW），中间是
      // 标准 chunk 方块（nodeW），恒单行。
      const xs = [
        layout.x,
        layout.x + layout.endW + layout.endGap,
        layout.x + layout.endW + layout.endGap + layout.nodeW + layout.endGap,
      ];
      return {
        x: xs[index],
        y: layout.y + BIN_VIEW.titleH + (layout.topPad || 0),
        row: 0,
        column: index,
        w: index === 1 ? layout.nodeW : layout.endW,
      };
    }
    const row = Math.floor(index / layout.perRow);
    const column = index % layout.perRow;
    return {
      x: layout.x + column * (layout.nodeW + BIN_VIEW.nodeGap),
      y: layout.y + BIN_VIEW.titleH + (layout.topPad || 0) + row * (layout.nodeH + BIN_VIEW.rowGap),
      row,
      column,
      w: layout.nodeW,
    };
  }


  function strokeArrowHead(g, x, y, angle, color) {
    g.save();
    g.fillStyle = color;
    g.beginPath();
    g.moveTo(x, y);
    g.lineTo(x - 7 * Math.cos(angle - 0.42), y - 7 * Math.sin(angle - 0.42));
    g.lineTo(x - 7 * Math.cos(angle + 0.42), y - 7 * Math.sin(angle + 0.42));
    g.closePath();
    g.fill();
    g.restore();
  }

  function drawSingleLink(g, from, to, layout, color) {
    const sameRow = from.row === to.row;
    const x1 = from.x + (from.w || layout.nodeW);
    const y1 = from.y + layout.nodeH / 2;
    const x2 = to.x;
    const y2 = to.y + layout.nodeH / 2;
    g.save();
    g.strokeStyle = color;
    g.lineWidth = 1.5;
    g.beginPath();
    if (sameRow) {
      g.moveTo(x1, y1);
      g.lineTo(x2, y2);
    } else {
      // 换行时用右侧折返线，仍然保留唯一 next 方向。
      const turnX = layout.x + layout.perRow * (layout.nodeW + BIN_VIEW.nodeGap) - BIN_VIEW.nodeGap + 10;
      g.moveTo(x1, y1);
      g.lineTo(turnX, y1);
      g.lineTo(turnX, y2 - layout.nodeH / 2 - 8);
      g.lineTo(layout.x - 12, y2 - layout.nodeH / 2 - 8);
      g.lineTo(layout.x - 12, y2);
      g.lineTo(x2, y2);
    }
    g.stroke();
    strokeArrowHead(g, x2, y2, 0, color);
    if (sameRow) {
      g.fillStyle = color;
      g.font = '8px "Cascadia Mono", Consolas, monospace';
      g.textAlign = 'center';
      g.fillText('next', (x1 + x2) / 2, y1 - 5);
      g.textAlign = 'left';
    }
    g.restore();
  }

  /**
   * 教科书式双链画法：
   *   fd/next —— 从本节点右侧 fd 格出发，弧线越过顶部，箭头扎在下一节点头顶；
   *   bk/prev —— 从下一节点左侧 bk 格出发，弧线绕过底部，箭头指回本节点脚底。
   * 相邻对与「尾 → arena」回环（closure=true，弧更高）共用同一几何。
   */
  function drawDoubleLinks(g, from, to, layout, color, closure = false) {
    const sideW = 25;
    const fromW = from.w || layout.nodeW;
    const toW = to.w || layout.nodeW;
    const bkColor = '#ff6f86';
    const fdColor = color;
    g.save();
    g.lineWidth = 1.4;
    if (from.row !== to.row) {
      // 跨行：fd 沿右缘绕行，从上方扎进目标头顶；bk 沿左缘绕行，从下方指回源节点脚底。
      const fdStart = { x: from.x + fromW - sideW / 2, y: from.y };
      const toTop = { x: to.x + toW / 2, y: to.y - 1 };
      const rightX = layout.x + layout.perRow * (layout.nodeW + BIN_VIEW.nodeGap) - BIN_VIEW.nodeGap + 12;
      const topY = Math.min(from.y, to.y) - 30;
      g.strokeStyle = fdColor;
      g.beginPath();
      g.moveTo(fdStart.x, fdStart.y);
      g.lineTo(rightX, fdStart.y);
      g.lineTo(rightX, topY);
      g.lineTo(toTop.x, topY);
      g.lineTo(toTop.x, toTop.y);
      g.stroke();
      strokeArrowHead(g, toTop.x, toTop.y, Math.PI / 2, fdColor);
      const bkStart = { x: to.x + sideW / 2, y: to.y + layout.nodeH };
      const fromBottom = { x: from.x + fromW / 2, y: from.y + layout.nodeH + 1 };
      const leftX = layout.x - 16;
      const botY = Math.max(from.y, to.y) + layout.nodeH + 30;
      g.strokeStyle = bkColor;
      g.beginPath();
      g.moveTo(bkStart.x, bkStart.y);
      g.lineTo(leftX, bkStart.y);
      g.lineTo(leftX, botY);
      g.lineTo(fromBottom.x, botY);
      g.lineTo(fromBottom.x, fromBottom.y);
      g.stroke();
      strokeArrowHead(g, fromBottom.x, fromBottom.y, -Math.PI / 2, bkColor);
      g.restore();
      return;
    }

    const arcOf = (startX, startY, endX, endY, color2, up) => {
      const dist = Math.max(70, Math.abs(endX - startX));
      const h = closure ? Math.min(50, Math.max(34, dist * 0.22))
        : Math.min(42, Math.max(20, dist * 0.2));
      const ctrl = { x: (startX + endX) / 2, y: up ? Math.min(startY, endY) - h : Math.max(startY, endY) + h };
      g.strokeStyle = color2;
      g.beginPath();
      g.moveTo(startX, startY);
      g.quadraticCurveTo(ctrl.x, ctrl.y, endX, endY);
      g.stroke();
      strokeArrowHead(g, endX, endY, Math.atan2(endY - ctrl.y, endX - ctrl.x), color2);
    };

    // fd：本节点 fd 槽顶 → 下一节点头顶（从上往下扎）。
    arcOf(
      from.x + fromW - sideW / 2, from.y,
      to.x + toW / 2, to.y - 1,
      fdColor, true,
    );
    // bk：下一节点 bk 槽底 → 本节点脚底（从下往上指）。
    arcOf(
      to.x + sideW / 2, to.y + layout.nodeH,
      from.x + fromW / 2, from.y + layout.nodeH + 1,
      bkColor, false,
    );
    g.restore();
  }
  function drawSingleNode(g, position, layout, item, color) {
    const { x, y } = position;
    const w = position.w || layout.nodeW;
    g.save();
    g.fillStyle = '#1e2225';
    g.strokeStyle = color;
    g.lineWidth = 1.4;
    g.beginPath();
    g.roundRect(x, y, w, layout.nodeH, 5);
    g.fill();
    g.stroke();
    g.textAlign = 'center';
    g.fillStyle = item.terminal ? COLORS.dim : COLORS.text;
    g.font = item.head ? 'bold 9px "Cascadia Mono", Consolas, monospace' : 'bold 11px "Cascadia Mono", Consolas, monospace';
    g.fillText(fitText(item.label, w - 10, g.font, g), x + w / 2, y + 14);
    if (item.address) {
      g.fillStyle = COLORS.dim;
      g.font = '8px "Cascadia Mono", Consolas, monospace';
      g.fillText(fitText(item.address, w - 8, g.font, g), x + w / 2, y + 28);
    }
    g.textAlign = 'left';
    g.restore();
  }
  function drawDoubleNode(g, position, layout, item, color) {
    const { x, y } = position;
    const w = position.w || layout.nodeW;
    const sideW = 25;
    g.save();
    g.fillStyle = '#211f27';
    g.strokeStyle = color;
    g.lineWidth = 1.4;
    g.beginPath();
    g.roundRect(x, y, w, layout.nodeH, 6);
    g.fill();
    g.stroke();
    if (!item.head) {
      // chunk 方块：bk / fd 两个槽位分隔线与标签。
      g.beginPath();
      g.moveTo(x + sideW, y);
      g.lineTo(x + sideW, y + layout.nodeH);
      g.moveTo(x + w - sideW, y);
      g.lineTo(x + w - sideW, y + layout.nodeH);
      g.strokeStyle = 'rgba(180, 180, 190, 0.36)';
      g.stroke();
      g.textAlign = 'center';
      g.font = 'bold 10px "Cascadia Mono", Consolas, monospace';
      g.fillStyle = '#ff6f86';
      g.fillText('bk', x + sideW / 2, y + 24);
      g.fillStyle = color;
      g.fillText('fd', x + w - sideW / 2, y + 24);
    }
    g.textAlign = 'center';
    g.font = 'bold 11px "Cascadia Mono", Consolas, monospace';
    // 有地址行时 label 靠上、地址靠下；没有地址（arena）时在方块内垂直居中。
    const labelY = item.address ? y + 16 : y + layout.nodeH / 2 + 4;
    g.fillStyle = item.head ? COLORS.dim : COLORS.text;
    g.fillText(fitText(item.label, item.head ? w - 8 : w - sideW * 2 - 6, g.font, g), x + w / 2, labelY);
    if (item.address) {
      g.fillStyle = COLORS.dim;
      g.font = '7.5px "Cascadia Mono", Consolas, monospace';
      g.fillText(fitText(item.address, w - sideW * 2 - 6, g.font, g), x + w / 2, y + 29);
    }
    g.textAlign = 'left';
    g.restore();
  }

  function drawBinDiagrams(g, step) {
    for (const layout of allBinLayouts(step)) {
      g.save();
      g.fillStyle = layout.color;
      g.font = 'bold 12px "Cascadia Mono", Consolas, monospace';
      g.fillText(`${layout.label}  count=${layout.chain.length}`, layout.x, layout.y + 12);
      g.fillStyle = COLORS.dim;
      g.font = '9px "Cascadia Mono", Consolas, monospace';
      g.fillText(layout.doubly ? 'circular doubly linked (fd / bk)' : 'singly linked next', layout.x, layout.y + 22);

      // 双链：以 arena 为哨兵的循环双链表。unsorted count=1（fd/bk 都是
      // arena）时前后各画一个 arena 方块，不画回环弧 —— fd/bk → arena 的
      // 关系由相邻箭头直接表达。其余双链只画一个 arena，fd/bk 用回环箭头
      // 闭合成环。单链：bin head → ... → NULL。
      const nodes = layout.doubly
        ? [
          { label: 'arena', address: '', head: true },
          ...layout.chain.map((id) => binNodeTruth(id, step)),
          ...(layout.arenaBookends ? [{ label: 'arena', address: '', head: true }] : []),
        ]
        : [
          { label: layout.label, address: '', head: true },
          ...layout.chain.map((id) => binNodeTruth(id, step)),
          { label: 'NULL', address: '', terminal: true },
        ];
      const positions = nodes.map((_, index) => chainNodePosition(layout, index));
      if (layout.doubly) {
        // 相邻对：fd 上弧向右，bk 下弧向左。
        for (let index = 0; index + 1 < positions.length; index += 1) {
          drawDoubleLinks(g, positions[index], positions[index + 1], layout, layout.color);
        }
        // 循环闭合：last.fd → arena，arena.bk → last（更高的弧，构成环）。
        // unsorted count=1 前后各有一个 arena，无需回环。
        if (!layout.arenaBookends) {
          drawDoubleLinks(g, positions[positions.length - 1], positions[0], layout, layout.color, true);
        }
      } else {
        for (let index = 0; index + 1 < positions.length; index += 1) {
          drawSingleLink(g, positions[index], positions[index + 1], layout, layout.color);
        }
      }
      nodes.forEach((item, index) => {
        if (layout.doubly) drawDoubleNode(g, positions[index], layout, item, layout.color);
        else drawSingleNode(g, positions[index], layout, item, layout.color);
      });
      g.restore();
    }
  }

  // bins 面板第二职责：当前步是 show 时，面板下部展示 show 的读取结果
  // （泄漏值 / 字节）。只在 show 步出现，其他步只画 bins。
  function stepShowObservation(step) {
    if (!step) return null;
    const op = (state.ops || []).find((item) => String(item.op_id || '') === String(step.op_id || ''));
    if (!op || op.kind !== 'show') return null;
    const shows = (step.observations || []).filter((item) => item && item.kind === 'show');
    return shows.length ? shows[shows.length - 1] : null;
  }

  function wrapMonoLines(text, maxWidth, charW) {
    const source = String(text ?? '');
    const cap = Math.max(12, Math.floor(maxWidth / charW));
    const lines = [];
    for (let index = 0; index < source.length; index += cap) {
      lines.push(source.slice(index, index + cap));
    }
    return lines.length ? lines : [''];
  }

  /** show 区块的几何（绘制与滚动钳制共用同一份计算，避免两处漂移）。 */
  function showSectionSpec(step) {
    const obs = stepShowObservation(step);
    if (!obs) return null;
    const width = Math.max(160, binsCssW - 24);
    const valueLines = wrapMonoLines(obs.value, width, 5.6);
    const detailLines = wrapMonoLines(obs.detail, width, 4.9);
    const height = 22
      + valueLines.length * 13
      + (obs.integer_value ? 16 : 0)
      + detailLines.length * 12 + 6;
    return { obs, valueLines, detailLines, height };
  }

  function binPanelBottom(step) {
    const base = binDiagramBottom(step);
    const spec = showSectionSpec(step);
    return spec ? base + 14 + spec.height : base;
  }

  function clampBinsScroll(nextY) {
    const step = state.steps[state.current];
    const bottom = step ? binPanelBottom(step) : 0;
    if (!bottom) return 0;
    const minY = Math.min(0, binsCssH - bottom - 12);
    return Math.max(minY, Math.min(0, Number(nextY) || 0));
  }

  /** bins 独立右栏画布：tcache/fastbin 单链，unsorted/small/large 双链；
   *  show 步时下方追加 show 读取结果。 */
  function drawBins() {
    if (!binsCtx) return;
    const step = state.steps[state.current];
    binsCtx.setTransform(binsDpr, 0, 0, binsDpr, 0, 0);
    binsCtx.fillStyle = COLORS.lane;
    binsCtx.fillRect(0, 0, binsCssW, binsCssH);
    if (!step) {
      binsCtx.fillStyle = COLORS.dim;
      binsCtx.font = '12px "Cascadia Mono", Consolas, monospace';
      binsCtx.fillText('bins 会在识别到堆操作后显示', 14, 24);
      return;
    }
    binsCtx.setTransform(binsDpr, 0, 0, binsDpr, 0, binsDpr * binsCamera.y);
    drawBinDiagrams(binsCtx, step);
    const spec = showSectionSpec(step);
    if (!spec) return;
    const g = binsCtx;
    const top = binDiagramBottom(step) + 14;
    g.save();
    g.fillStyle = COLORS.text;
    g.font = 'bold 11px "Cascadia Mono", Consolas, monospace';
    g.fillText(`show · ${spec.obs.name} = ${spec.obs.expression}`, 12, top + 11);
    g.font = '9px "Cascadia Mono", Consolas, monospace';
    g.fillStyle = COLORS.dim;
    spec.valueLines.forEach((line, index) => {
      g.fillText(line, 12, top + 25 + index * 13);
    });
    let cursorY = top + 25 + spec.valueLines.length * 13;
    if (spec.obs.integer_value) {
      g.fillStyle = '#4ec9b0';
      g.font = 'bold 10px "Cascadia Mono", Consolas, monospace';
      g.fillText(`→ ${spec.obs.integer_value}`, 12, cursorY + 3);
      cursorY += 16;
    }
    g.fillStyle = COLORS.dim;
    g.font = '8.5px "Cascadia Mono", Consolas, monospace';
    spec.detailLines.forEach((line, index) => {
      g.fillText(line, 12, cursorY + 4 + index * 12);
    });
    g.restore();
  }

  function hitGridCell(body, point) {
    // 命中测试：点在 chunk 网格的哪一行/半格 → 字段地址
    const chunk = body.data && body.data.chunk;
    const step = state.steps[state.current];
    if (!chunk || !step) return null;
    const grid = cachedChunkGrid(chunk, step, state.editMode);
    if (grid.base === null) return null;
    const relY = point.y - body.y;
    const relX = point.x - body.x;
    if (relX < 0 || relX > GRID.cardW || relY < GRID.titleH) return null;
    let cy = GRID.titleH;
    for (const row of grid.rows) {
      const h = row.kind === 'marker' ? GRID.markerH : GRID.rowH;
      if (relY >= cy && relY < cy + h) {
        if (row.kind === 'marker') return { address: null, row, field: null, value: null };
        const half = relX >= GRID.cardW / 2 ? 1 : 0;
        // partial row 的越界 cell：没有物理字节，不参与选中/编辑
        const userRel = row.off - grid.word * 2 + half * grid.word;
        if (userRel >= grid.userBytes) return null;
        const offset = grid.base + row.off + half * grid.word;
        const field = fieldAtOffset(chunk, offset);
        const value = cellValue(chunk, grid, offset, half);
        const address = field ? field.address : addAddressOffset(chunk.address, row.off + half * grid.word);
        return { address, offset, row, half, field, value };
      }
      cy += h;
    }
    return null;
  }

  function hitBody(x, y) {
    for (let i = world.bodies.length - 1; i >= 0; i -= 1) {
      const body = world.bodies[i];
      if (x >= body.x && x <= body.x + body.w && y >= body.y && y <= body.y + body.h) return body;
    }
    return null;
  }

  /** 行右下角 ⊕ 命中：返回命中行与其 user 区插入偏移（区别于顶/底边 ●）。 */
  function hitRowInsertButton(point) {
    if (!state.editMode) return null;
    const step = state.steps[state.current];
    if (!step) return null;
    for (const body of world.bodies) {
      const chunk = body.data && body.data.chunk;
      if (!structurallyEditableChunk(chunk)) continue;
      const grid = cachedChunkGrid(chunk, step, state.editMode);
      let cy = body.y + GRID.titleH;
      for (const row of grid.rows) {
        const rowH = row.kind === 'marker' ? GRID.markerH : GRID.rowH;
        if (row.kind !== 'marker') {
          const cx = body.x + GRID.cardW - 13;
          const cyc = cy + rowH / 2;
          if (Math.hypot(point.x - cx, point.y - cyc) <= 9) {
            const afterUserOffset = row.kind === 'header'
              ? 0
              : (row.index + 1) * grid.userRowBytes;
            return {
              body, chunk, row,
              rowKey: row.kind === 'header' ? 'hdr' : `u${row.index}`,
              afterUserOffset,
              rowCenterY: cyc,
              rowBottomY: cy + rowH,
            };
          }
        }
        cy += rowH;
      }
    }
    return null;
  }

  /** 顶/底边中央圆形 resize handle 命中（首个 chunk 顶边锁定）。 */
  function hitResizeHandle(point) {
    if (!state.editMode) return null;
    const step = state.steps[state.current];
    if (!step) return null;
    for (const body of world.bodies) {
      const chunk = body.data && body.data.chunk;
      if (!structurallyEditableChunk(chunk)) continue;
      const cx = body.x + body.w / 2;
      const lockTop = isFirstPhysicalChunk(chunk, step);
      for (const edge of ['top', 'bottom']) {
        if (edge === 'top' && lockTop) continue;
        const cy = edge === 'top' ? body.y : body.y + body.h;
        if (Math.hypot(point.x - cx, point.y - cy) <= RESIZE_HANDLE_HIT) {
          return { body, chunk, edge };
        }
      }
    }
    return null;
  }

  /** 编辑模式状态条：拒绝原因 / 待确认标记的常驻出口（日志之外的第二个通道）。 */
  function heapEditStatus(text, isError) {
    const node = $('#heap-edit-status');
    if (!node) return;
    if (!text) {
      node.hidden = true;
      node.textContent = '';
      return;
    }
    node.hidden = false;
    node.textContent = text;
    node.classList.toggle('error', Boolean(isError));
    if (isError) {
      clearTimeout(heapEditStatus.timer);
      heapEditStatus.timer = setTimeout(() => heapEditStatus(''), 8000);
    }
  }

  function showRejection(reason) {
    heapEditStatus(`⛔ ${reason}`, true);
    log(`结构编辑被拒绝：${reason}`, 'error');
  }

  /** 结构事务结果统一出口：拒绝→状态条；成功→原子提交 + 学习/待确认静默记录。 */
  function absorbStructuralResult(result, chunk, label, stepForState) {
    if (result && result.ok === false) {
      showRejection(result.reason || '未知原因');
      return false;
    }
    const step = Number.isFinite(stepForState) ? stepForState : state.current;
    absorbState(result, label, true, { currentStep: result.selected_step ?? step });
    const edit = result.structural_edit || {};
    if (edit.exp_reason) {
      // 反向映射不可证明时绝不编造 EXP 代码：物理修改保留，标记待映射 EXP。
      log(`待映射 EXP：${edit.exp_reason}`, 'warn');
      heapEditStatus(`⏳ 待映射 EXP：${edit.exp_reason}`, false);
    }
    for (const rule of (result.learning && result.learning.learned_rules_added) || []) {
      log(`✓ 学习：${rule.reason}`);
    }
    log(`${chunk.chunk_id} 结构事务已提交；后继 chunk、bins、top 已由 Python 整体重建。`);
    return true;
  }

  /** 边界拖动提交：RESIZE_PHYSICAL 事务（word 步进，引擎侧 Constraint 校验）。 */
  async function commitResize(chunk, edge, delta) {
    if (state.structuralPending) return;
    state.structuralPending = true;
    heapEditStatus('结构事务执行中…', false);
    try {
      const result = await window.pwnbao.request('heap_structural_edit', {
        step: state.current,
        kind: 'RESIZE_PHYSICAL',
        chunk_id: chunk.chunk_id,
        physical_id: chunk.physical_id,
        delta,
        edge,
      });
      const label = `STRUCTURAL ${chunk.chunk_id} ${edge} ${delta >= 0 ? '+' : '-'}0x${Math.abs(delta).toString(16)}`;
      if (absorbStructuralResult(result, chunk, label, state.current + 1)) {
        state.selectedPhysicalId = chunkBodyKey(chunk);
      }
    } catch (error) {
      showRejection(error.message);
    } finally {
      state.structuralPending = false;
      needsDraw = true;
    }
  }

  // -- Draft Row：点击行右下角 ⊕ 只打开待插入物理行的草稿弹窗（纯前端
  // 草稿层，不进 PhysicalMemory / snapshot / 学习）；点「完成」通过后端
  // 约束校验才以 INSERT_USER_ROW 事务原子插入，取消不修改任何状态。
  function openDraftRow(hit) {
    const { chunk, body, row, rowKey, afterUserOffset, rowBottomY } = hit;
    if (!chunk || state.draftRow || !body) return;
    const step = state.steps[state.current];
    if (!step) return;
    const word = archWord();
    const userLen = Math.max(0, (chunkSizeTriple(chunk).physicalExtentSize || 0) - word * 2);
    const isMid = afterUserOffset < userLen;
    state.draftRow = {
      chunk, body, row, rowKey, afterUserOffset, userLen,
      bottomY: Number.isFinite(rowBottomY) ? rowBottomY : body.y + body.h,
    };
    const host = canvasHost;
    if (!host || $('#heap-draft-row')) return;
    const offsetLabel = formatOffset(afterUserOffset);
    const node = el('div');
    node.id = 'heap-draft-row';
    node.innerHTML = `
      <span class="draft-title">+1 row · ${esc(chunk.chunk_id)} · 插入到 ${offsetLabel} 之前</span>
      <input id="draft-cell-0" class="input draft-cell" placeholder="低字 0x..（${isMid ? '必填' : '可留空'}）" />
      <input id="draft-cell-1" class="input draft-cell" placeholder="高字 0x..（${isMid ? '必填' : '可留空'}）" />
      <button id="draft-commit" class="btn primary">完成</button>
      <button id="draft-cancel" class="btn">取消</button>
      <span class="hint-dim">${isMid
        ? '中插的新物理行没有旧值可保留：两个格子都必须填写，之后字节整体下移'
        : 'Esc 取消 · 留空的格子保持 untouched，不伪造字节'}</span>`;
    host.appendChild(node);
    positionDraftRow();
    $('#draft-commit').addEventListener('click', () => commitDraftRow());
    $('#draft-cancel').addEventListener('click', () => closeDraftRow());
    $('#draft-cell-0').focus();
    node.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeDraftRow();
      if (event.key === 'Enter') commitDraftRow();
    });
    needsDraw = true;
  }

  function positionDraftRow() {
    const node = $('#heap-draft-row');
    if (!node || !state.draftRow) return;
    const { body, bottomY } = state.draftRow;
    // 贴在被点行下方 +4px：预告新行将要出现的位置，不遮住原行
    node.style.left = `${Math.round(body.x + state.camera.x + 4)}px`;
    node.style.top = `${Math.round(bottomY + state.camera.y + 4)}px`;
  }

  function closeDraftRow() {
    state.draftRow = null;
    const node = $('#heap-draft-row');
    if (node) node.remove();
    needsDraw = true;
  }

  async function commitDraftRow() {
    const draft = state.draftRow;
    if (!draft || state.structuralPending) return;
    const { chunk, afterUserOffset, userLen } = draft;
    const word = archWord();
    const values = [$('#draft-cell-0'), $('#draft-cell-1')].map((input) => {
      const text = (input && input.value ? input.value : '').trim();
      if (!text) return null;
      const parsed = parseBig(text);
      if (parsed === null || parsed < 0n || parsed >= (1n << BigInt(word * 8))) {
        showRejection(`单元格值 "${text}" 不是 0..2^${word * 8}-1 的整数`);
        throw new Error('bad-cell');
      }
      return parsed;
    });
    // 只取连续已填前缀；留空格子 = untouched 字节，绝不补 0 冒充。
    let filled = 0;
    while (filled < values.length && values[filled] !== null) filled += 1;
    const isMid = afterUserOffset < userLen;
    if (isMid && filled !== values.length) {
      // 中插的新物理字节没有旧值可保留：留空无法诚实表达，硬拒绝。
      showRejection('中插必须提供完整行字节：两个格子都填写（留空会被伪造 0，拒绝）');
      return;
    }
    if (filled < values.length && values[values.length - 1] !== null) {
      showRejection('存在空洞：先填左侧格子，或把右侧留空');
      return;
    }
    const bytes = new Uint8Array(filled * word);
    for (let index = 0; index < filled; index += 1) {
      let value = values[index];
      for (let byteIndex = 0; byteIndex < word; byteIndex += 1) {
        bytes[index * word + byteIndex] = Number(value & 0xffn);
        value >>= 8n;
      }
    }
    const grid = cachedChunkGrid(chunk, state.steps[state.current], state.editMode);
    state.structuralPending = true;
    heapEditStatus('结构事务执行中…', false);
    try {
      const result = await window.pwnbao.request('heap_structural_edit', {
        step: state.current,
        kind: 'INSERT_USER_ROW',
        chunk_id: chunk.chunk_id,
        physical_id: chunk.physical_id,
        delta: grid.userRowBytes,
        after_user_offset: afterUserOffset,
        data_hex: Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join(''),
      });
      const label = `STRUCTURAL ${chunk.chunk_id} INSERT@${formatOffset(afterUserOffset)} ${formatOffset(grid.userRowBytes)}`;
      if (absorbStructuralResult(result, chunk, label, state.current)) {
        state.selectedPhysicalId = chunkBodyKey(chunk);
        closeDraftRow();
      }
    } catch (error) {
      if (error.message !== 'bad-cell') showRejection(error.message);
    } finally {
      state.structuralPending = false;
      needsDraw = true;
    }
  }

  // -- 边界命中：编辑模式下顶/底边中央圆形 handle，纵向拖动按 word 吸附
  //（amd64 每格 0x8，i386 每格 0x4）；提交后经 Python 事务校验。
  const RESIZE_HANDLE_RADIUS = 7;
  const RESIZE_HANDLE_HIT = 11;
  const resizeStepBytes = () => archWord();

  /** 第一个 chunk 的上边界锁定（堆起始边界，引擎同样拒绝）。 */
  function isFirstPhysicalChunk(chunk, step) {
    const myOff = chunkOffsetValue(chunk, null);
    if (myOff === null) return false;
    return !stepChunks(step).some((item) => {
      if (item.chunk_id === chunk.chunk_id) return false;
      if (item.view_kind === 'top_chunk' || item.view_kind === 'fake_chunk') return false;
      const off = chunkOffsetValue(item, null);
      return off !== null && off < myOff;
    });
  }

  /**
   * 边界位移（boundaryDelta）：>0 = 边界向下，<0 = 边界向上。
   * 直接吸附到 PhysicalGrid 的 cell 边界 —— 1 cell = 半行 = GRID.rowH/2
   * 像素 ↔ word 字节（amd64 0x8 / i386 0x4）。禁止用 extent/bodyHeight
   * 把像素按比例换算字节：行高固定，cell 换算是精确的。
   */
  function resizeDeltaBytes(drag) {
    const dy = drag.currentY - drag.startY;
    const cellPx = GRID.rowH / 2;
    const step = resizeStepBytes();
    return Math.round(dy / cellPx) * step;
  }

  /** chunk 内物理偏移 → 卡内世界 y（行高固定：1 word = 半行 = cellPx）。 */
  function offsetToWorldY(body, chunk, offset) {
    const base = chunkOffsetValue(chunk, null);
    const rel = Math.max(0, offset - (base === null ? 0 : base));
    const word = archWord();
    const cellPx = GRID.rowH / 2;
    if (rel < word * 2) return body.y + (rel / word) * cellPx;
    return body.y + GRID.titleH + ((rel - word * 2) / word) * cellPx;
  }

  /**
   * 真实物理 overlap 预览：目标物理区间 [newStart, newEnd) ∩ 相邻 chunk
   * 的物理范围 —— 与正式 paint_spans 同一区间计算，只把真正进入对方
   * 物理范围的 cell 标红。绝不做像素估算。
   */
  function computeResizePreview(chunk, edge, boundaryDelta) {
    if (!boundaryDelta) return null;
    const step = state.steps[state.current];
    const myOff = chunkOffsetValue(chunk, null);
    const extent = chunkSizeTriple(chunk).physicalExtentSize;
    if (myOff === null || !extent) return null;
    const newStart = edge === 'top' ? myOff + boundaryDelta : myOff;
    const newEnd = edge === 'bottom' ? myOff + extent + boundaryDelta : myOff + extent;
    if (newEnd - newStart <= 0) return null;
    const bands = [];
    let overlap = false;
    for (const item of stepChunks(step)) {
      if (item.chunk_id === chunk.chunk_id) continue;
      if (item.view_kind === 'top_chunk' || item.view_kind === 'fake_chunk') continue;
      const off = chunkOffsetValue(item, null);
      const ext = chunkSizeTriple(item).physicalExtentSize || 0;
      if (off === null || !ext) continue;
      const start = Math.max(newStart, off);
      const end = Math.min(newEnd, off + ext);
      if (end <= start) continue;
      const body = bodiesByChunk.get(chunkBodyKey(item));
      if (!body) continue;
      overlap = true;
      bands.push({
        kind: 'overlap',
        x: body.x, w: body.w,
        y0: offsetToWorldY(body, item, start),
        y1: offsetToWorldY(body, item, end),
      });
    }
    const selfBody = bodiesByChunk.get(chunkBodyKey(chunk));
    if (selfBody) {
      const yA = offsetToWorldY(selfBody, chunk, Math.min(newStart, myOff + extent));
      const yB = offsetToWorldY(selfBody, chunk, Math.max(newStart, myOff + extent));
      if (yB > yA) {
        bands.push({ kind: boundaryDelta > 0 ? 'grow' : 'shrink', x: selfBody.x, w: selfBody.w, y0: yA, y1: yB });
      }
    }
    return { bands, overlap };
  }

  function canvasPoint(event) {
    const rect = canvas.getBoundingClientRect();
    return {
      x: event.clientX - rect.left - state.camera.x,
      y: event.clientY - rect.top - state.camera.y,
    };
  }

  // 布局拖动（整块 visual_y 拖动）已移除：物理编辑模式里 overlap 关系
  // 不能被视觉位移弄乱。state.canvasLayout 只保留读取以兼容旧场景。

  function bindCanvas() {
    // 每个画布元素只绑一次（render() 重建 DOM 后旧监听器随旧节点销毁）。
    if (!canvas || canvas.dataset.canvasBound) return;
    canvas.dataset.canvasBound = '1';
    canvas.addEventListener('wheel', (event) => {
      event.preventDefault();
      // 滚轮 = 上下滚动画布（不缩放，尺寸固定且可读）。
      // 事件里只累计标准化 delta + 请求重绘；相机更新由 tick 每帧统一消费
      //（wheel coalescing）。绝不能漏 needsDraw —— 否则 camera 变了画面不动。
      const unit = event.deltaMode === 1 ? 16 : (event.deltaMode === 2 ? cssH : 1);
      pendingWheelDelta += (event.deltaY || 0) * unit;
      needsDraw = true;
    }, { passive: false });
    if (binsCanvas) {
      binsCanvas.addEventListener('wheel', (event) => {
        event.preventDefault();
        // bins 面板独立纵向滚动
        const unit = event.deltaMode === 1 ? 16 : (event.deltaMode === 2 ? binsCssH : 1);
        binsCamera.y = clampBinsScroll(binsCamera.y - (event.deltaY || 0) * unit);
        binsNeedsDraw = true;
      }, { passive: false });
    }
    canvas.addEventListener('mousedown', async (event) => {
      const point = canvasPoint(event);
      // 编辑模式命中优先级：顶/底 ●（改物理边界）> 行 ⊕（插行）>
      // cell（选中/再点编辑）> 头部带（画布布局拖动）。三类编辑彻底分开。
      if (!state.structuralPending && !state.draftRow) {
        const handle = hitResizeHandle(point);
        if (handle) {
          drag = {
            mode: 'resize', body: handle.body, chunk: handle.chunk,
            edge: handle.edge, startY: point.y, currentY: point.y, moved: false,
          };
          canvas.style.cursor = 'ns-resize';
          event.preventDefault();
          return;
        }
      }
      const rowInsert = hitRowInsertButton(point);
      if (rowInsert) {
        event.preventDefault();
        openDraftRow(rowInsert);
        return;
      }
      const body = hitBody(point.x, point.y);
      if (!body || !body.data || body.data.kind !== 'chunk') return;
      const chunk = body.data.chunk;
      state.selectedPhysicalId = chunkBodyKey(chunk);
      // 物理编辑模式禁止整块拖动（布局拖动已移除）：visual_y 不再写入，
      // 卡片永远按物理 flush 顺序排布，overlap 关系不会被视觉位移弄乱。
      // 单元格：第一次点击选中高亮；再点同一格 = 编辑该 cell 真实值
      const cell = hitGridCell(body, point);
      if (cell && cell.address !== null) {
        const cellKey = { bodyKey: chunkBodyKey(chunk), off: cell.row.off, half: cell.half };
        const same = state.selectedCell
          && state.selectedCell.bodyKey === cellKey.bodyKey
          && state.selectedCell.off === cellKey.off
          && state.selectedCell.half === cellKey.half;
        if (state.editMode && same) {
          showCorrectionDialog(chunk, cell);
          needsDraw = true;
          return;
        }
        state.selectedCell = { ...cellKey, cell };
        if (state.editMode) {
          heapEditStatus(
            `已选中 ${chunk.chunk_id} +0x${(cell.row.off + cell.half * archWord()).toString(16)} · 再点一次编辑该格真实值`,
            false,
          );
        }
        locateField(cell.address);
      } else {
        state.selectedCell = null;
        locateChunk(chunk.chunk_id);
      }
      needsDraw = true;
    });
    canvas.addEventListener('mousemove', (event) => {
      const point = canvasPoint(event);
      if (drag && drag.mode === 'resize') {
        drag.currentY = point.y;
        drag.moved = true;
        // boundaryDelta：>0 = 边界向下，<0 = 向上（鼠标往哪拖边界往哪走）
        const delta = resizeDeltaBytes(drag);
        state.guides = [point.y];
        state.resizePreview = delta === 0 ? null : computeResizePreview(drag.chunk, drag.edge, delta);
        const extent = chunkSizeTriple(drag.chunk).physicalExtentSize || 0;
        const newExtent = extent + (drag.edge === 'top' ? -delta : delta);
        heapEditStatus(
          `${drag.chunk.chunk_id} ${drag.edge === 'top' ? '上' : '下'}边界 ${delta >= 0 ? '↓' : '↑'} 0x${Math.abs(delta).toString(16)}`
          + ` · extent 0x${extent.toString(16)}→${newExtent > 0 ? '0x' + newExtent.toString(16) : '—'}`
          + `（松手提交，${resizeStepBytes()} 字节/cell 吸附）`,
          false,
        );
        needsDraw = true;
        return;
      }
      const rowInsert = hitRowInsertButton(point);
      const next = rowInsert ? `${chunkBodyKey(rowInsert.chunk)}:${rowInsert.rowKey}` : null;
      const handle = !drag && !state.draftRow ? hitResizeHandle(point) : null;
      const overHandle = handle ? `${chunkBodyKey(handle.chunk)}:${handle.edge}` : null;
      if (state.hoveredRowInsert !== next) {
        state.hoveredRowInsert = next;
      }
      if (state.hoveredResize !== overHandle) {
        state.hoveredResize = overHandle;
      }
      canvas.style.cursor = next ? 'pointer' : (overHandle ? 'ns-resize' : 'default');
      needsDraw = true;
    });
    window.addEventListener('mouseup', () => {
      if (drag && drag.mode === 'resize') {
        const { chunk, edge } = drag;
        const delta = resizeDeltaBytes(drag);
        state.guides = null;
        state.resizePreview = null;
        drag = null;
        canvas.style.cursor = 'default';
        if (delta !== 0 && !state.structuralPending) {
          commitResize(chunk, edge, delta);
        } else {
          heapEditStatus('');
        }
      }
      if (state.draftRow) positionDraftRow();
      needsDraw = true;
    });
    // 键盘：Enter = 编辑当前选中格（等效第二次单击）；Esc = 取消选中。
    // 草稿弹窗自己处理 Enter/Esc，这里必须让路（draftRow 活跃 / 焦点在输入框）。
    window.addEventListener('keydown', (event) => {
      if (state.draftRow) return;
      const tag = event.target && event.target.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (event.key === 'Escape') {
        if (state.selectedCell) {
          state.selectedCell = null;
          needsDraw = true;
        }
        return;
      }
      if (event.key === 'Enter' && state.editMode && state.selectedCell) {
        const body = bodiesByChunk.get(state.selectedCell.bodyKey);
        if (!body || !body.data || !body.data.chunk) return;
        showCorrectionDialog(body.data.chunk, state.selectedCell.cell);
      }
    });
  }

  // =====================================================================
  // Correction (canvas edit → truth → replay → learned rules)

  function correctionTargetForCell(chunk, cell) {
    const fields = chunk.fields || [];
    if (cell && cell.field) return cell.field;
    if (cell && cell.address) {
      const gridOffset = relativeOffset(chunk.address, displayOffsetForChunk(chunk, state.steps[state.current], 0));
      const chunkRelative = Number.isFinite(gridOffset) && Number.isFinite(cell.offset)
        ? cell.offset - gridOffset : 0;
      const name = cell.row && cell.row.kind === 'header'
        ? (cell.half === 0 ? 'prev_size' : 'size')
        : `user[0x${Math.max(0, chunkRelative - archWord() * 2).toString(16)}]`;
      return {
        name,
        value: cell.value && cell.value.value ? cell.value.value : 'unknown',
        address: cell.address,
        provenance: cell.value && cell.value.provenance ? cell.value.provenance : 'unknown',
        synthetic: true,
      };
    }
    return fields[0] || {
      name: 'user[0x0]', value: 'unknown',
      address: addAddressOffset(chunk.address, archWord() * 2),   // user 区起点 = header 两个 word
      provenance: 'unknown', synthetic: true,
    };
  }

  function showCorrectionDialog(chunk, cell = null) {
    const field = correctionTargetForCell(chunk, cell);
    const logicalOffset = cell && Number.isFinite(cell.offset)
      ? cell.offset
      : relativeOffset(field.address, displayOffsetForChunk(chunk, state.steps[state.current], 0));
    const chunkBase = displayOffsetForChunk(chunk, state.steps[state.current], 0);
    const relativeInChunk = Number.isFinite(logicalOffset) && Number.isFinite(chunkBase)
      ? logicalOffset - chunkBase : null;
    const currentValue = field.value || (cell && cell.value && cell.value.value) || 'unknown';
    const targetLabel = [
      `chunk ${chunk.chunk_id}`,
      field.name || 'user_area',
      formatOffset(logicalOffset),
      relativeInChunk !== null ? `chunk+0x${relativeInChunk.toString(16)}` : '',
    ].filter(Boolean).join(' · ');
    const inferred = fieldName(field.name || 'user_area');
    const byteDefault = inferred === 'user_area' ? '' : 'display:none';
    // helper/canonOp 必须在弹窗渲染前解析（回调里复用同一份，不重复声明）。
    const op = state.steps[state.current];
    const helper = helperForStep(op);
    const canonOp = (state.canonicalOps || []).find((item) => Number(item.step) === state.current) || {};
    const helperKnown = helper !== 'UNKNOWN_HELPER';
    const helperHint = helperKnown
      ? `helper：${esc(helper)}（后端将带形参名/角色绑定/邻域调用交给学习引擎）`
      : '当前步骤 helper 未识别（UNKNOWN_HELPER）：本次校正按物理观测纠错处理，不会污染契约学习。';
    openDialog(`编辑 ${chunk.chunk_id} · ${field.name || 'user_area'}`, `
      <div class="corr-target-card">
        <div><b>正在校正：</b><span class="mono">${esc(targetLabel)}</span></div>
        <div class="hint-dim">地址：${esc(field.address || '?')} · 当前值：${esc(currentValue)} · 来源：${esc(field.provenance || 'unknown')}</div>
        <div class="hint-dim">${helperHint}</div>
      </div>
      <label class="form-row"><span>新值</span><input id="dlg-corr-value" class="input" placeholder="0x71 / 113 / 0xdeadbeef" /></label>
      <label class="form-row" style="${byteDefault}"><span>字节文本</span><input id="dlg-corr-text" class="input" placeholder="b'AAAA' 或 AAAA" /></label>
      <label class="form-row"><span>说明（可选）</span><input id="dlg-corr-note" class="input" placeholder="例如：这里是 B.size，被 A overflow 覆盖" /></label>
      <div class="hint-dim">已按你点中的格子自动带上 chunk、字段、chunk 内偏移、物理对象和当前值；后续识别/校正实时重算，不需要单独切模式。</div>
    `, async () => {
      const valueText = $('#dlg-corr-value').value.trim();
      const byteInput = $('#dlg-corr-text');
      const byteText = byteInput ? byteInput.value.trim() : '';
      const note = $('#dlg-corr-note').value.trim();
      const patch = {
        address: field.address,
        field: inferred,
        object_id: chunk.physical_id,
        note,
      };
      if (byteText) {
        const raw = byteText.startsWith("b'") || byteText.startsWith('b"')
          ? byteText.slice(2, -1) : byteText;
        patch.data_hex = [...new TextEncoder().encode(raw)].map((b) => b.toString(16).padStart(2, '0')).join('');
        patch.length = patch.data_hex.length / 2;
        patch.field = 'user_area';
      } else if (valueText) {
        patch.value_int = asInt(valueText);
        patch.length = isPointerField(field.name) ? archWord() : guessWidth(field.name);
        if (isPointerField(field.name)) patch.decoded_pointer = true;
      } else {
        log('校正需要新值或字节文本。', 'warn');
        return;
      }
      const corrStep = state.current;
      // VNext.3.1B: Canvas 编辑意图分裂 — 校正真值 vs 草稿推演是两条管线
      let canvasIntent = 'correction';
      const intentChoice = window.prompt(
        '这次编辑表达什么？\n' +
        '  correction  = 真实状态校正（分析错了，我知道实际值）\n' +
        '  assumption  = 仅作为利用假设推演（不进入学习管线）\n' +
        '  直接回车 = correction', 'correction');
      if (intentChoice === null) return; // 取消
      canvasIntent = (intentChoice.trim() || 'correction').toLowerCase();
      if (!['correction', 'assumption'].includes(canvasIntent)) {
        log(`未知编辑意图 ${canvasIntent}，按 correction 处理。`, 'warn');
        canvasIntent = 'correction';
      }
      try {
        const result = await window.pwnbao.request('heap_correct', {
          step: corrStep,
          intent: canvasIntent,
          patch,
          context: {
            // UNKNOWN_HELPER 绝不上送：后端按「无 helper 信息」处理，
            // 不会生成 function=UNKNOWN_HELPER 的学习规则。
            helper: helper === 'UNKNOWN_HELPER' ? '' : helper,
            kind: opKindOfCurrent(),
            corrected_kind: opKindOfCurrent(),
            // Correction context v2：学习器需要的调用点形态。形参名 /
            // 指纹 / 当前角色绑定由后端从源码补齐，这里带上已知部分。
            source_line: Number(canonOp.source_line) || 0,
            source_call: canonOp.source_call || '',
            allocator_profile_id: (state.allocator || {}).profile_id || '',
            selected_chunk: chunk.chunk_id,
            physical_id: chunk.physical_id,
            selected_field: field.name || patch.field,
            selected_offset: relativeInChunk !== null ? `0x${relativeInChunk.toString(16)}` : '',
            selected_address: field.address || '',
            before_value: currentValue,
            provenance: field.provenance || 'unknown',
            row_kind: cell && cell.row ? cell.row.kind : '',
            // 用户说明就是最直接的意图提示（resolver 只认三个枚举值，
            // 自由文本不会误触发否决，但会随 episode 落盘）。
            intent_hint: note,
          },
        });
        if (!result.accepted) {
          log(`校正被拒绝：${(result.issues || []).join('；')}`, 'error');
          return;
        }
        // 原子提交：后端返回整包 heap_state（steps 全量 + operations + 学习结果），
        // 画布/操作表/学习面板永远来自同一 snapshot，不再手动 splice 后缀。
        commitSnapshot(result.heap_state || result, state.sceneOrigin.startsWith('STRUCTURAL') ? state.sceneOrigin : 'CORRECTED', { currentStep: corrStep, announce: false });
        log('修改已应用，后续状态已实时重算。', 'info');
        if (result.learning) showLearningResult(result.learning);
        // Semantic Round Trip：画布物理写入 → 反向求解 → 待应用步骤
        if (patch.field === 'user_area' || patch.field === 'size') {
          await solvePendingFromPatch(corrStep, patch);
        }
      } catch (error) {
        log(`校正失败：${error.message}`, 'error');
      }
    });
  }

  const INTENT_LABELS = {
    semantic_contract: '语义识别纠错 · HelperContract',
    observed_state: '物理状态纠错 · ObservedState',
    derivation_rule: '推导规则纠错 · LearnedRule',
  };

  function showLearningResult(learning) {
    const intent = learning.intent || 'observed_state';
    const badgeClass = intent === 'semantic_contract' ? 'good'
      : intent === 'derivation_rule' ? 'warn' : 'neutral';
    const candidates = (learning.candidates || []).map((candidate) => `
      <div class="learn-candidate ${candidate.kind === intent ? 'chosen' : ''}">
        <div class="lc-head">
          <span class="lc-kind">${esc(candidate.kind)}</span>
          <span class="flex-spacer"></span>
          <span class="lc-strength">证据强度 ${candidate.strength}</span>
        </div>
        <div class="lc-detail">${esc(candidate.detail)}</div>
        <div class="lc-evidence">${(candidate.evidence || []).map((item) => `<span class="lc-ev">${esc(item)}</span>`).join('')}</div>
      </div>`).join('');
    const learned = learning.learned || {};
    const effectLines = `
      <div class="explain-line"><b>学到了：</b>${esc(learned.effect || '')}</div>
      ${learned.roles ? `<div class="explain-line">契约角色：${esc(Object.entries(learned.roles)
    .map(([role, binding]) => `${role} ← ${(binding || {}).parameter || '?'}@${(binding || {}).position}`)
    .join('， '))}</div>` : ''}
      ${learning.reanalyzed ? '<div class="explain-line">✅ 本题已按新识别<b>整题重算</b>，后续识别优先参考该结果。</div>'
    : '<div class="explain-line">影响范围：本题该 checkpoint 之后的运行状态。</div>'}`;
    app().openDialog('Correction Learning Engine · 学习结果', `
      <div class="learn-result">
        <div class="explain-line">
          意图判定：<span class="sec-val ${badgeClass}">${esc(INTENT_LABELS[intent] || intent)}</span>
          · 置信度 <b>${esc(learning.confidence || '')}</b> · scope ${esc(learning.scope || 'scene')}
        </div>
        <div class="explain-line hint-dim">${esc(learning.reasoning || '')}</div>
        <div class="sidebar-mini-title">候选与证据链</div>
        ${candidates}
        <div class="sidebar-mini-title">学习效果</div>
        ${effectLines}
      </div>
    `, null, '知道了');
  }

  function fieldName(name) {
    const cleanName = String(name || 'user_area');
    if (cleanName === 'fd/next') return 'next';
    if (cleanName === 'bk/key') return 'bk';
    if (cleanName.startsWith('size')) return 'size';
    if (cleanName.startsWith('prev_size')) return 'prev_size';
    if (cleanName.startsWith('user')) return 'user_area';
    return cleanName.toLowerCase();
  }

  function isPointerField(name) {
    return ['fd', 'next', 'bk', 'key'].includes(fieldName(name));
  }

  function guessWidth(name) {
    const clean = fieldName(name);
    if (clean === 'size' || clean === 'prev_size') return archWord();
    return archWord();
  }

  function asInt(text) {
    const clean = String(text).trim();
    if (/^-?\d+$/.test(clean)) return clean;
    return BigInt(clean.startsWith('0x') || clean.startsWith('-0x') ? clean : `0x${clean}`).toString(10);
  }

  function opKindOfCurrent() {
    const step = state.steps[state.current];
    if (!step) return '';
    const opId = step.op_id;
    const op = ((state.heapState && state.heapState.operations) || []).find((item) => item.op_id === opId);
    return op ? op.kind : '';
  }

  /**
   * helper 名不再硬编码 malloc→add / free→delete。优先级：
   * ① Canonical IR 的 source_call（识别器绑定的真实 EXP 调用文本）
   * ② 已确认的 HelperContract（USER_CONFIRMED）
   * ③ UNKNOWN_HELPER —— 识别器明确承认不知道。旧的语义缺省名
   *   （free→delete / 否则→add）是猜测：它会混进 Correction Learning 的
   *   helper 字段污染学习数据。先承认不知道，纠正才能变成有效监督信号。
   */
  function helperForStep(step) {
    const kind = opKindOfCurrent();
    const canon = (state.canonicalOps || []).find((item) => Number(item.step) === state.current);
    if (canon && canon.source_call) {
      const match = /^([A-Za-z_]\w*)\s*\(/.exec(String(canon.source_call));
      if (match) return match[1];
    }
    const contracts = (state.heapState && state.heapState.helper_contracts) || [];
    const semantic = kind === 'alloc' ? 'alloc' : kind;
    const contract = contracts.find((item) => String(item.operation || '') === semantic);
    if (contract && contract.function) return String(contract.function);
    return 'UNKNOWN_HELPER';
  }

  async function undoCorrection() {
    try {
      const result = await window.pwnbao.request('heap_undo_correction');
      if (result && result.ok === false) {
        log(result.message || '没有可撤销的校正。', 'warn');
        return;
      }
      absorbState(result, 'UNDO');
      log('已撤销上一次画布校正并重放。');
    } catch (error) {
      log(`撤销失败：${error.message}`, 'error');
    }
  }

  // ---------------------------------------------------------------------
  // 训练数据层：Case Export（generated/）与 Agent Review（review/ 层）。
  // review 只进独立标签层，验证通过也不改 Snapshot —— 快照永远只来自
  // 显式的 allocator 事务。

  async function exportTrainingCase() {
    try {
      const arch = (window.PwnApp && window.PwnApp.arch) || 'amd64';
      const defaultName = `${(state.heapState && state.heapState.name) || 'heap场景'}.case.json`;
      const path = await window.pwnbao.pickSavePath(defaultName, 'json');
      if (!path) return;
      const result = await window.pwnbao.request('heap_export_case', {
        path,
        target: { arch },
        challenge_family: '',
      });
      const validation = result.validation || {};
      const engine = ((result.case || {}).engine) || {};
      if (validation.valid) {
        log(`训练 Case 已导出并通过校验：${path}（engine ${engine.version} · ${engine.recognizer_revision} · ${engine.allocator_profile_id}）`);
      } else {
        log(`训练 Case 已导出，但校验发现问题：${(validation.issues || []).join('；')}`, 'warn');
      }
    } catch (error) {
      log(`Case 导出失败：${error.message}`, 'error');
    }
  }

  async function importAgentReview() {
    try {
      const path = await window.pwnbao.pickOpenPath('json');
      if (!path) return;
      const result = await window.pwnbao.request('heap_import_review', { path });
      await refreshReviewLayer();
      log(`Agent Review 已导入：${result.review.review_id}（${result.review.issue_type}）· 快照未改动。`);
    } catch (error) {
      log(`Review 导入失败：${error.message}`, 'error');
    }
  }

  async function applyAgentReview(reviewId, humanConfirmed) {
    try {
      const result = await window.pwnbao.request('heap_apply_review', {
        review_id: reviewId, human_confirmed: Boolean(humanConfirmed),
      });
      await refreshReviewLayer();
      const review = result.review || {};
      const issues = ((review.validation || {}).issues) || [];
      log(`Review ${reviewId} → ${review.verdict}`
        + (issues.length ? `：${issues.join('；')}` : ''), review.verdict === 'rejected' ? 'warn' : 'info');
    } catch (error) {
      log(`Review 验证失败：${error.message}`, 'error');
    }
  }

  /** Review 验证只动标签层：重取整包状态并原位提交（origin 仍属 LEARNED 族）。 */
  async function refreshReviewLayer() {
    const fresh = await window.pwnbao.request('heap_state');
    absorbState(fresh, 'LEARNED REVIEW', true, { announce: false });
    renderLearnSummary();
  }

  // =====================================================================
  // Scene persistence

  async function saveScene() {
    try {
      const defaultName = `${(state.heapState && state.heapState.name) || 'heap场景'}.json`;
      const path = await window.pwnbao.pickSavePath(defaultName, 'json');
      if (!path) return;
      await window.pwnbao.request('heap_save', { path });
      log(`堆场景已保存：${path}`);
    } catch (error) {
      log(`场景保存失败：${error.message}`, 'error');
    }
  }

  async function openScene() {
    try {
      const path = await window.pwnbao.pickOpenPath('json');
      if (!path) return;
      const heapState = await window.pwnbao.request('heap_open', { path });
      absorbState(heapState, 'SCENE', false, { resetLayout: true });
      switchTab('canvas');
    } catch (error) {
      log(`场景打开失败：${error.message}`, 'error');
    }
  }

  function switchTab(which) {
    state.tab = which === 'iofile' ? 'iofile' : 'canvas';
    $('#heap-canvas-row').hidden = state.tab !== 'canvas';
    $('#heap-iofile-page').hidden = state.tab !== 'iofile';
    const button = $('#heap-iofile');
    if (button) button.classList.toggle('primary', state.tab === 'iofile');
    if (state.tab === 'iofile') renderIoFilePage();
  }

  // =====================================================================
  // IO FILE page (typed FILE views; lives beside the heap canvas on purpose:
  // FILE structures are heap/arena neighbours and the canvas can open a chunk
  // "作为 _IO_FILE 打开")
  //
  // TargetContext 只有一个当前 libc：IO FILE 的 glibc 版本跟随 Heap 的
  // allocator profile（effective_version），不再各玩各的。在这里切版本 =
  // 切全局 profile（触发同一个 Reprofile 事务）。

  function effectiveIoFileVersion() {
    const allocator = state.allocator || {};
    // 已提交场景只相信生效版本；还没有场景时跟随选择器的请求值。
    return allocator.effective_version || allocator.version || selectedGlibcVersion();
  }

  async function renderIoFilePage() {
    const host = $('#heap-iofile-page');
    if (!host) return;
    host.innerHTML = '<div class="hint-dim" style="padding:16px">加载 glibc 布局中…</div>';
    try {
      const layout = await window.pwnbao.request('iofile_layout', {
        version: effectiveIoFileVersion(),
        bits: (window.PwnApp && window.PwnApp.bits) || (state.allocator || {}).bits || 64,
      });
      state.iofile.layout = layout;
      const expSource = (window.PwnApp && window.PwnApp.getExpText()) || '';
      const analysis = expSource
        ? await window.pwnbao.request('iofile_analyze', { source: expSource })
        : { evidence: [] };

      // 三个 symbol 各自独立的 values/status，互不串味
      const store = iofileStore();
      const rows = [...layout.fields, ...layout.wide_fields].map((field) => {
        const value = store.values[field.name] || '';
        const status = store.status[field.name];
        return `
          <tr data-field="${esc(field.name)}">
            <td class="mono">+0x${field.offset.toString(16).padStart(2, '0')}</td>
            <td class="mono">${esc(field.name)}</td>
            <td>${esc(field.kind)}</td>
            <td><input class="input iofile-value" data-field="${esc(field.name)}"
                       value="${esc(value)}" placeholder="未观测" /></td>
            <td class="iofile-status ${status ? esc(status.status.toLowerCase()) : ''}">${status ? esc(status.status) : ''}</td>
          </tr>`;
      }).join('');

      host.innerHTML = `
        <div class="iofile-toolbar">
          <label class="inline-label">glibc
            <select id="iofile-version" class="input" title="与 Heap 共用 TargetContext profile：在这里切版本同样触发全局 Reprofile">
              ${(layout.supported_versions || ['2.23', '2.27', '2.31', '2.32', '2.34', '2.35', '2.36', '2.37', '2.38', '2.39', '2.40'])
    .map((v) => `<option${v === effectiveIoFileVersion() ? ' selected' : ''}>${v}</option>`).join('')}
            </select>
          </label>
          <label class="inline-label">symbol
            <select id="iofile-symbol" class="input">
              ${['stdout', 'stderr', 'stdin'].map((s) => `<option${s === state.iofile.symbol ? ' selected' : ''}>${s}</option>`).join('')}
            </select>
          </label>
          <span class="hint-dim">字段写入受 FileConstraintEngine 约束：structural_pointer 需通过对齐检查；未提供映射时不伪造「已验证映射」。</span>
        </div>
        <div class="iofile-table-wrap">
          <table class="iofile-table">
            <thead><tr><th>Offset</th><th>Field</th><th>Kind</th><th>Value</th><th>Validation</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div class="iofile-evidence">
          <div class="sidebar-mini-title">EXP / FILE 证据（AST，静态）</div>
          ${analysis.evidence.length
    ? analysis.evidence.map((item) => `<div class="corr-row"><div class="corr-line">L${item.line} · ${esc(item.symbol)} · ${esc(item.expression)}</div></div>`).join('')
    : '<div class="hint-dim">exp.py 中暂无 FILE 相关写入证据。</div>'}
        </div>`;

      $('#iofile-version').addEventListener('change', async (event) => {
        // 同一个 TargetContext：IO FILE 页切版本 = 全局 profile 切换
        //（heap_reprofile 事务）。这里总是重渲染：成功时展示新 profile
        // 布局，失败/未生效时回显真正生效的版本（Truth Sync）。
        await changeGlibcProfile(event.target.value);
        if (state.tab === 'iofile') renderIoFilePage();
      });
      $('#iofile-symbol').addEventListener('change', (event) => {
        state.iofile.symbol = event.target.value;
        renderIoFilePage();
      });
      // 响应里的生效版本可能与所选不同（≥2.40 会钳到 2.40）：把选中项校正为真值
      const versionSelect = $('#iofile-version');
      if (versionSelect && layout.version && [...versionSelect.options].some((o) => o.value === layout.version)) {
        versionSelect.value = layout.version;
      }
      host.querySelectorAll('.iofile-value').forEach((input) => {
        input.addEventListener('change', async () => {
          const name = input.dataset.field;
          const value = input.value.trim();
          const current = iofileStore();
          if (!value) { delete current.values[name]; delete current.status[name]; return; }
          current.values[name] = value;
          try {
            const result = await window.pwnbao.request('iofile_validate', {
              version: effectiveIoFileVersion(),
              symbol: state.iofile.symbol,
              name,
              value,
              values: current.values,
              observed: true,
            });
            current.status[name] = { status: result.status, issues: result.issues };
            log(`IOFILE ${state.iofile.symbol}.${name}: ${result.status}${result.issues && result.issues.length ? ' · ' + result.issues.join('；') : ''}`,
              result.status === 'INVALID' ? 'error' : 'info');
          } catch (error) {
            current.status[name] = { status: 'INVALID', issues: [error.message] };
          }
          renderIoFilePage();
        });
      });
    } catch (error) {
      host.innerHTML = `<div class="hint-dim" style="padding:16px">IOFILE 布局加载失败：${esc(error.message)}</div>`;
    }
  }

  function iofileStore() {
    if (!state.iofile.bySymbol[state.iofile.symbol]) {
      state.iofile.bySymbol[state.iofile.symbol] = { values: {}, status: {} };
    }
    return state.iofile.bySymbol[state.iofile.symbol];
  }

  // =====================================================================
  // Dialog + log plumbing (shared via PwnApp when available)

  function openDialog(title, bodyHtml, onOk) {
    if (window.PwnApp && window.PwnApp.openDialog) {
      window.PwnApp.openDialog(title, bodyHtml, onOk);
      return;
    }
    // minimal fallback
    const value = window.prompt(title);
    if (value !== null && onOk) onOk();
  }

  function log(message, level) {
    if (window.PwnApp && window.PwnApp.log) window.PwnApp.log(message, level);
    else console.log(`[heap] ${message}`);
  }

  // =====================================================================
  // Boot

  async function boot() {
    if (window.PwnApp && window.PwnApp.setExpHeapLineHandler) {
      window.PwnApp.setExpHeapLineHandler(handleExpCursorLine);
    }
    render();
    await loadTemplates();
    // 不自动装演示模板：画布内容来源必须明确（用户 exp / 用户操作 / 显式加载模板）
    updateOrigin('空');
  }

  window.PwnHeap = {
    boot,
    loadTemplate,
    replayExp,
    autoReplayFromExp,
    stepTo,
    get state() { return state; },
    exportRendererPlan,      // P0-5: 当前 step 的真实渲染计划（复用真几何管线）
    rebuildAndPlan,          // headless: 重建 world 后导出（Electron smoke / node harness）
  };
  // 调试探针：body 矩形 + 身份 key（测试/诊断用，不含任何编辑语义）
  window.__heapProbeBodies = () => world.bodies.map((body) => ({
    x: body.x, y: body.y, w: body.w, h: body.h,
    key: body.data && body.data.chunk ? chunkBodyKey(body.data.chunk) : '',
    id: body.data && body.data.chunk ? body.data.chunk.chunk_id : '',
  }));
})();
