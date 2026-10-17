import '@material/web/button/filled-button.js';
import '@material/web/button/filled-tonal-button.js';
import '@material/web/button/outlined-button.js';
import '@material/web/button/text-button.js';
import '@material/web/dialog/dialog.js';
import '@material/web/icon/icon.js';
import '@material/web/iconbutton/icon-button.js';
import '@material/web/progress/linear-progress.js';
import '@material/web/radio/radio.js';
import '@material/web/select/outlined-select.js';
import '@material/web/select/select-option.js';
import '@material/web/switch/switch.js';
import '@material/web/textfield/outlined-text-field.js';
import { argbFromHex, themeFromSourceColor, applyTheme } from '@material/material-color-utilities';
import YAML from 'yaml';
import symbolsFont from './font-data.js';
import codexIcon from './codex-icon-data.js';
import licenseText from './license-text-data.js';
import './native-bridge.js';
import './styles.css';

const fontStyle = document.createElement('style');
fontStyle.textContent = `@font-face{font-family:'Material Symbols Rounded';font-style:normal;font-weight:400;font-display:swap;src:url("${symbolsFont}") format('woff2')}`;
document.head.append(fontStyle);

const root = document.querySelector('#app');
const hiddenIp = '********';
const modeLabels = { clash: 'Clash 订阅配置', vps: 'VPS / 单节点配置' };
const layoutPositionLabels = {
  editor: '编辑区', top: '上方', right: '右侧', bottom: '下方', left: '左侧',
};
const protocols = [
  ['trojan-tls', 'Trojan + TLS'],
  ['trojan-ws', 'Trojan + WebSocket + TLS'],
  ['vless-ws', 'VLESS + WebSocket + TLS'],
  ['vless-reality', 'VLESS + Reality'],
  ['ss', 'Shadowsocks'],
  ['vmess-ws', 'VMess + WebSocket + TLS'],
];
const schemeNames = ['primary', 'on-primary', 'primary-container', 'on-primary-container',
  'secondary', 'on-secondary', 'secondary-container', 'on-secondary-container',
  'tertiary', 'on-tertiary', 'tertiary-container', 'on-tertiary-container',
  'surface', 'surface-container-low', 'surface-container', 'surface-container-high',
  'surface-container-highest', 'on-surface', 'on-surface-variant', 'outline',
  'outline-variant', 'inverse-surface', 'inverse-on-surface', 'inverse-primary',
  'error', 'on-error', 'error-container', 'on-error-container'];

let database;
const state = {
  screen: 'loading', reverse: false, busy: false, profiles: [], selectedId: null,
  mode: 'clash', draft: freshDraft('clash'), search: '', showSecret: false,
  exitIp: { value: null, visible: false, loading: false, error: '', checkedAt: null },
  settings: { installationMode: 'service', desktopPath: '', desktopSource: '', enabled: false, cliPathMismatch: false,
    activeProfileId: null, theme: 'system', accent: 'auto', layoutPosition: 'editor', railRatio: 24, dockRatio: 48, nodeHeight: 200, sourceCollapsed: false, railCollapsed: false },
  draggingLayout: false, layoutPointerId: null,
};

function freshDraft(kind) {
  return kind === 'clash'
    ? { id: null, kind, name: '', url: '', fetchedUrl: '', source: '', nodes: [], selectedNodeId: '' }
    : { id: null, kind, name: '', protocol: 'trojan-tls', server: '', port: '443',
        credential: '', sni: '', path: '/', host: '', publicKey: '', shortId: '', cipher: 'aes-128-gcm' };
}

function esc(value = '') {
  return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
}
function ico(name, slot = '') { return `<md-icon${slot ? ` slot="${slot}"` : ''}>${name}</md-icon>`; }
function option(value, text, selected) { return `<md-select-option value="${esc(value)}" ${selected ? 'selected' : ''}><div slot="headline">${esc(text)}</div></md-select-option>`; }
function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function id() { return crypto.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`; }

async function openStore() {
  if (!('indexedDB' in window)) return null;
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('codex-proxy-web-preview', 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta', { keyPath: 'key' });
      if (!db.objectStoreNames.contains('profiles')) db.createObjectStore('profiles', { keyPath: 'id' });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
function dbRequest(store, method, value) {
  return new Promise((resolve, reject) => {
    const tx = database.transaction(store, method === 'get' || method === 'getAll' ? 'readonly' : 'readwrite');
    const request = tx.objectStore(store)[method](value);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function loadSaved() {
  if (window.codexProxy?.native) {
    const saved = await window.codexProxy.request('loadState');
    state.settings = { ...state.settings, ...saved.settings };
    state.profiles = saved.profiles || [];
    return;
  }
  try { database = await openStore(); } catch { database = null; }
  if (database) {
    const [settings, profiles] = await Promise.all([dbRequest('meta', 'get', 'settings'), dbRequest('profiles', 'getAll')]);
    if (settings) state.settings = { ...state.settings, ...settings.value };
    state.profiles = profiles.sort((a, b) => b.updatedAt - a.updatedAt);
  } else {
    try {
      state.settings = { ...state.settings, ...JSON.parse(localStorage.getItem('codex-preview-settings') || '{}') };
      state.profiles = JSON.parse(localStorage.getItem('codex-preview-profiles') || '[]');
    } catch { /* Keep an empty, usable preview. */ }
  }
}
async function persistSettings() {
  if (window.codexProxy?.native) { await window.codexProxy.request('saveSettings', state.settings); return; }
  if (database) await dbRequest('meta', 'put', { key: 'settings', value: state.settings });
  else localStorage.setItem('codex-preview-settings', JSON.stringify(state.settings));
}
async function persistProfile(profile) {
  if (window.codexProxy?.native) { await window.codexProxy.request('saveProfile', profile); return; }
  if (database) await dbRequest('profiles', 'put', profile);
  else localStorage.setItem('codex-preview-profiles', JSON.stringify(state.profiles));
}
async function removeProfile(profileId) {
  if (window.codexProxy?.native) { await window.codexProxy.request('removeProfile', profileId); return; }
  if (database) await dbRequest('profiles', 'delete', profileId);
  else localStorage.setItem('codex-preview-profiles', JSON.stringify(state.profiles));
}

function systemAccent() {
  if (!window.CSS?.supports?.('color', 'AccentColor')) return null;
  const probe = document.createElement('span');
  probe.style.color = 'AccentColor';
  probe.style.position = 'absolute';
  probe.style.visibility = 'hidden';
  document.body.append(probe);
  const rgb = getComputedStyle(probe).color;
  probe.remove();
  const numbers = rgb.match(/\d+/g)?.slice(0, 3).map(Number);
  return numbers?.length === 3 ? `#${numbers.map(n => n.toString(16).padStart(2, '0')).join('')}` : null;
}
function applyColors() {
  const dark = state.settings.theme === 'dark' || (state.settings.theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
  schemeNames.forEach(name => document.documentElement.style.removeProperty(`--md-sys-color-${name}`));
  const accent = state.settings.accent === 'auto' ? systemAccent() : null;
  if (accent) {
    try { applyTheme(themeFromSourceColor(argbFromHex(accent)), { target: document.documentElement, dark }); }
    catch { /* The supplied purple scheme remains in CSS. */ }
  }
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', getComputedStyle(document.documentElement).getPropertyValue('--md-sys-color-surface').trim());
}

function toast(message, error = false) {
  document.querySelector('.toast')?.remove();
  const el = document.createElement('div');
  el.className = `toast${error ? ' error' : ''}`;
  el.role = error ? 'alert' : 'status';
  el.textContent = message;
  document.body.append(el);
  setTimeout(() => el.remove(), 5000);
}
async function withOperation(label, action) {
  if (state.busy) return;
  state.busy = true;
  const overlay = document.createElement('div');
  overlay.className = 'operation-overlay';
  overlay.setAttribute('role', 'status');
  overlay.setAttribute('aria-live', 'polite');
  overlay.innerHTML = `<div class="operation-card"><span class="operation-spinner" aria-hidden="true"></span><strong>${esc(label)}</strong></div>`;
  document.body.append(overlay);
  root.setAttribute('aria-busy', 'true');
  try {
    // Let WebView paint the indicator before a native dialog or other UI-thread work starts.
    await Promise.race([
      new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))),
      delay(100),
    ]);
    return await action();
  } finally {
    overlay.remove();
    root.removeAttribute('aria-busy');
    state.busy = false;
  }
}
function fail(error) {
  const message = error instanceof Error ? error.message : String(error);
  const field = state.screen === 'desktop' && document.querySelector('[data-field="desktopPath"]');
  if (field) { field.error = true; field.errorText = message; field.focus(); return; }
  toast(message, true);
}
function navigate(screen, reverse = false) {
  state.screen = screen;
  state.reverse = reverse;
  history.pushState({ screen }, '', location.href);
  render();
}

function renderLoading() {
  return `<main class="shell screen ${state.reverse ? 'reverse' : ''}"><div class="loading-frame">
    <div class="loading-content">${ico('settings_suggest')}<h1>正在载入配置工作区</h1>
      <md-linear-progress indeterminate aria-label="正在加载配置"></md-linear-progress>
      <p>读取用户配置</p></div></div></main>`;
}

function renderGate() {
  return `<main class="shell screen ${state.reverse ? 'reverse' : ''}"><section class="gate"><div class="gate-card">
    <div class="gate-top"><div class="gate-emblem"><img src="${codexIcon}" alt="Codex" /></div>
      <md-icon-button data-action="theme-cycle" title="切换浅色、深色或跟随系统" aria-label="切换主题">${ico('contrast')}</md-icon-button></div>
    <p class="eyebrow" style="margin-top:30px">桌面文件 · 首次设置</p>
    <h1>桌面版路径</h1>
    <p class="supporting">选择 ChatGPT 桌面程序，继续配置专属代理。</p>
    <div class="gate-fields"><div class="gate-path"><md-outlined-text-field data-field="desktopPath" label="路径" value="${esc(state.settings.desktopPath)}" supporting-text="文件名须为 ChatGPT.exe。"></md-outlined-text-field></div>
      <md-outlined-button data-action="locate-desktop">${ico('search', 'icon')}自动定位</md-outlined-button></div>
    <div class="gate-actions"><md-outlined-button data-action="choose-desktop">${ico('folder_open', 'icon')}选择桌面文件</md-outlined-button>
      <md-filled-button data-action="enter-main">${ico('arrow_forward', 'icon')}进入主界面</md-filled-button></div>
    <input id="desktop-picker" type="file" accept=".exe" hidden />
  </div></section></main>`;
}

function profileTitle(profile) { return profile?.name?.trim() || '未命名配置'; }
function renderProfileRail() {
  const query = state.search.trim().toLocaleLowerCase();
  const profiles = state.profiles.filter(p => p.kind === state.mode && profileTitle(p).toLocaleLowerCase().includes(query));
  return `<aside class="profile-rail" id="profile-rail" ${state.settings.railCollapsed ? 'inert aria-hidden="true"' : ''}><div class="rail-head"><strong>已保存的配置</strong><span>${state.profiles.filter(p => p.kind === state.mode).length} 项</span></div>
    <md-outlined-text-field id="profile-search" label="搜索配置" type="search" value="${esc(state.search)}">${ico('search', 'leading-icon')}</md-outlined-text-field>
    <div class="profile-list">${profiles.length ? profiles.map(p => `<button class="profile-item pressable ${state.selectedId === p.id ? 'selected' : ''}" data-action="select-profile" data-id="${esc(p.id)}">
      ${ico(p.kind === 'clash' ? 'cloud_sync' : 'dns')}<span><strong>${esc(profileTitle(p))}</strong><small>${p.kind === 'clash' ? `${p.nodes?.length || 0} 个节点` : esc(protocols.find(x => x[0] === p.protocol)?.[1] || '手动节点')}${state.settings.enabled && state.settings.activeProfileId === p.id ? ' · 使用中' : ''}</small></span></button>`).join('')
      : `<div class="empty-list"><div>${ico('inventory_2')}<span>${query ? '没有匹配的配置' : '还没有保存的配置'}<br>${query ? '试试其他关键词。' : '在右侧填写后点击下方保存。'}</span></div></div>`}</div>
    <div class="rail-bottom"><md-outlined-button data-action="new-profile">${ico('add', 'icon')}新建${state.mode === 'clash' ? '订阅' : '节点'}</md-outlined-button></div>
  </aside>`;
}
function textField(key, label, opts = {}) {
  const value = state.draft[key] ?? '';
  return `<md-outlined-text-field data-field="${key}" label="${esc(label)}" value="${esc(value)}" ${opts.type ? `type="${opts.type}"` : ''} ${opts.disabled ? 'disabled' : ''} ${opts.support ? `supporting-text="${esc(opts.support)}"` : ''}></md-outlined-text-field>`;
}
function renderNodes() {
  const nodes = state.draft.nodes || [];
  return `<div class="section-heading"><strong>选择以后使用的节点</strong><small>${nodes.length ? `发现 ${nodes.length} 个可用节点` : '尚未添加节点'}</small></div>
    ${nodes.length ? `<div class="node-list">${nodes.map(node => `<label class="node-row pressable"><md-radio name="node" value="${esc(node.id)}" ${node.id === state.draft.selectedNodeId ? 'checked' : ''}></md-radio><span class="node-copy"><strong>${esc(node.name)}</strong><small>${esc(node.type.toUpperCase())} · ${esc(node.server)}:${esc(node.port)}</small></span>${ico('chevron_right')}</label>`).join('')}</div>`
    : `<div class="node-empty">${ico('hub')}获取订阅或导入文件后，在这里选择一个节点。</div>`}`;
}
function renderClashEditor() {
  const placement = layoutPositionLabels[state.settings.layoutPosition] || layoutPositionLabels.editor;
  return `<section class="clash-source-box layout-panel"><div class="panel-drag-handle" data-layout-panel role="button" tabindex="0" aria-label="拖动订阅与节点配置框以改变布局">
      ${ico('drag_pan')}<span><strong>拖动布局</strong><small>拖到工作区边缘可换位置 · 当前：${placement}</small></span><md-icon>open_with</md-icon></div>
    <div class="source-box-head"><div><p class="eyebrow">统一配置区</p><h3>订阅与节点</h3></div>
      <span class="source-box-badge">${state.draft.nodes?.length || 0} 个节点</span></div>
    <div class="form-grid"><div class="wide">${textField('name', '配置名称')}</div>
      <div class="wide field-with-action">${textField('url', 'HTTPS Clash 订阅链接', { type: state.showSecret ? 'text' : 'password', support: '订阅链接只保存在你的电脑上，不会上传。' })}
        <md-text-button class="field-action" data-action="show-secret">${ico(state.showSecret ? 'visibility_off' : 'visibility', 'icon')}${state.showSecret ? '隐藏' : '显示'}</md-text-button></div></div>
    <div class="inline-actions"><md-filled-tonal-button data-action="fetch-nodes">${ico('sync', 'icon')}获取 / 刷新节点</md-filled-tonal-button>
      <md-outlined-button data-action="import-file">${ico('upload_file', 'icon')}导入 Clash 文件</md-outlined-button>
      <md-outlined-button data-action="import-clipboard">${ico('content_paste', 'icon')}导入剪贴板节点</md-outlined-button></div>
    <p class="form-note">支持 Clash YAML / JSON 和常见分享链接。</p>
    <div class="node-box">${renderNodes()}</div>${resizeHandle('nodes', '上下拖动调整节点列表高度')}<input id="clash-picker" type="file" accept=".yaml,.yml,.json,.txt" hidden /></section>`;
}
function renderLayoutPlaceholder() {
  return `<div class="layout-placeholder">${ico('inbox')}<strong>暂无配置</strong></div>`;
}
function renderLayoutDropZones() {
  return `<div class="layout-drop-layer" aria-label="布局放置区域">
    <div class="layout-drop-zone zone-top" data-layout-slot="top">${ico('north')}<span>放到上方</span></div>
    <div class="layout-drop-zone zone-left" data-layout-slot="left">${ico('west')}<span>放到左侧</span></div>
    <div class="layout-drop-zone zone-editor" data-layout-slot="editor">${ico('center_focus_strong')}<span>放回编辑区</span></div>
    <div class="layout-drop-zone zone-right" data-layout-slot="right">${ico('east')}<span>放到右侧</span></div>
    <div class="layout-drop-zone zone-bottom" data-layout-slot="bottom">${ico('south')}<span>放到下方</span></div>
  </div>`;
}
function renderVpsEditor() {
  const d = state.draft;
  const ws = ['trojan-ws', 'vless-ws', 'vmess-ws'].includes(d.protocol);
  const reality = d.protocol === 'vless-reality';
  const ss = d.protocol === 'ss';
  return `<div class="form-grid">
    <md-outlined-select data-field="protocol" label="协议">${protocols.map(([key, label]) => option(key, label, d.protocol === key)).join('')}</md-outlined-select>
    ${textField('name', '节点名称')}
    ${textField('server', '服务器地址')}${textField('port', '端口', { type: 'number' })}
    <div class="field-with-action">${textField('credential', ss ? '密码' : ['vless-ws', 'vless-reality', 'vmess-ws'].includes(d.protocol) ? 'UUID' : '密码', { type: state.showSecret ? 'text' : 'password' })}
      <md-text-button class="field-action" data-action="show-secret">${ico(state.showSecret ? 'visibility_off' : 'visibility', 'icon')}${state.showSecret ? '隐藏' : '显示'}</md-text-button></div>
    ${textField('sni', 'TLS 域名', { disabled: ss, support: '留空时使用服务器地址。' })}
    ${textField('path', 'WS 路径', { disabled: !ws })}${textField('host', 'WS Host', { disabled: !ws })}
    ${textField('publicKey', 'Reality 公钥', { disabled: !reality })}${textField('shortId', 'Short ID', { disabled: !reality })}
    ${textField('cipher', 'SS 加密方式', { disabled: !ss })}
  </div>`;
}
function resizeHandle(kind, label) {
  return `<div class="resize-handle resize-${kind}" data-resize="${kind}" role="separator" tabindex="0" aria-label="${label}" title="${label}（方向键操作，双击复位）" ${kind === 'rail' ? `aria-controls="profile-rail" aria-valuenow="${state.settings.railCollapsed ? 0 : state.settings.railRatio}"` : ''}><span></span>${kind === 'rail' ? ico(state.settings.railCollapsed ? 'chevron_right' : 'chevron_left') : ''}</div>`;
}
function renderExitIp() {
  const { value, visible, loading, error, checkedAt } = state.exitIp;
  const label = state.mode === 'clash' ? '所选订阅节点出口 IP' : '当前节点出口 IP';
  const address = !visible ? hiddenIp : loading ? '正在检测…' : error ? '检测失败' : value || '尚未检测';
  const detail = visible && error ? error : visible && checkedAt
    ? `${new Date(checkedAt).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })} 更新`
    : '点击显示';
  return `<section class="exit-ip-card" aria-label="${label}">
    <div class="exit-ip-icon">${ico('public')}</div>
    <div class="exit-ip-copy"><span class="exit-ip-label">${label}</span>
      <strong class="exit-ip-value" aria-live="polite">${esc(address)}</strong>
      <small class="exit-ip-detail ${error && visible ? 'is-error' : ''}">${esc(detail)}</small></div>
    <div class="exit-ip-actions"><button type="button" class="exit-ip-toggle" data-action="toggle-exit-ip" aria-label="${visible ? '隐藏' : '显示'}出口 IP" aria-pressed="${visible}">
      ${ico(visible ? 'visibility_off' : 'visibility')}<span>${visible ? '隐藏' : '显示'}</span></button>
      ${visible ? `<button type="button" class="exit-ip-refresh" data-action="refresh-exit-ip" aria-label="刷新出口 IP" title="刷新出口 IP" ${loading ? 'disabled' : ''}>${ico('refresh')}</button>` : ''}</div>
  </section>`;
}
function renderMain() {
  const selected = state.profiles.find(p => p.id === state.settings.activeProfileId);
  const current = state.selectedId ? '编辑配置' : '新建配置';
  const isClash = state.mode === 'clash';
  const layoutPosition = isClash && layoutPositionLabels[state.settings.layoutPosition] ? state.settings.layoutPosition : 'editor';
  const panelOutside = isClash && layoutPosition !== 'editor';
  const editorContent = isClash ? (panelOutside ? renderLayoutPlaceholder(layoutPosition) : renderClashEditor()) : renderVpsEditor();
  return `<main class="shell screen ${state.reverse ? 'reverse' : ''}"><div class="workspace ${state.settings.sourceCollapsed ? 'source-collapsed' : ''}">
    <header class="hero"><div class="hero-left"><div class="brand-mark">${ico('terminal')}</div><span class="brand-copy">Codex Proxy</span></div>
      <h1>桌面版 CLI 配置</h1><div class="hero-actions"><span class="theme-caption">${state.settings.theme === 'system' ? '跟随系统' : state.settings.theme === 'dark' ? '深色模式' : '浅色模式'}</span>
      <md-text-button class="hero-button" data-action="theme-cycle">${ico('contrast', 'icon')}主题</md-text-button>
      <md-text-button class="hero-button" data-action="settings">${ico('settings', 'icon')}设置</md-text-button></div></header>
    <div class="mode-switcher" id="source-panel" ${state.settings.sourceCollapsed ? 'inert aria-hidden="true"' : ''}><div class="mode-summary"><span class="mode-avatar">${ico('person')}</span><span class="mode-copy"><strong>配置来源</strong><small>${state.settings.enabled && selected ? `当前使用：${esc(profileTitle(selected))}` : '设置 CLI 专属代理'}</small></span></div>
      <div class="mode-tabs" role="tablist" aria-label="配置来源">
        ${state.mode === 'clash' ? `<md-filled-tonal-button data-action="set-mode" data-mode="clash" role="tab" aria-selected="true">${ico('cloud_sync', 'icon')}Clash 订阅</md-filled-tonal-button>` : `<md-outlined-button data-action="set-mode" data-mode="clash" role="tab" aria-selected="false">${ico('cloud_sync', 'icon')}Clash 订阅</md-outlined-button>`}
        ${state.mode === 'vps' ? `<md-filled-tonal-button data-action="set-mode" data-mode="vps" role="tab" aria-selected="true">${ico('dns', 'icon')}VPS / 单节点</md-filled-tonal-button>` : `<md-outlined-button data-action="set-mode" data-mode="vps" role="tab" aria-selected="false">${ico('dns', 'icon')}VPS / 单节点</md-outlined-button>`}</div>${renderExitIp()}</div>
    <div class="resize-handle resize-source" data-resize="source" role="separator" tabindex="0" aria-orientation="horizontal" aria-controls="source-panel" aria-label="${state.settings.sourceCollapsed ? '向下拖动展开上方配置区' : '向上拖动收起上方配置区'}" aria-valuenow="${state.settings.sourceCollapsed ? 0 : 100}" title="${state.settings.sourceCollapsed ? '向下拖动展开上方配置区' : '向上拖动收起上方配置区'}（方向键操作，双击展开）"><span></span><small class="source-handle-copy">${state.settings.sourceCollapsed ? '向下拖动展开上方' : '向上拖动收起上方'}</small>${ico(state.settings.sourceCollapsed ? 'keyboard_arrow_down' : 'keyboard_arrow_up')}</div>
    <div class="layout-canvas ${isClash ? `layout-${layoutPosition}` : 'layout-single'}" data-layout-canvas>
      ${panelOutside ? renderClashEditor() : ''}
      <section class="config-card"><div class="card-head"><div><p class="eyebrow">配置工作区 / ${state.mode === 'clash' ? 'Clash' : 'VPS'}</p>
        <h2>${state.mode === 'clash' ? '订阅与节点' : '手动配置节点'}</h2><p class="supporting">${state.mode === 'clash' ? '导入节点，选一个作为出口并保存。' : '输入你的服务器参数，保存为一个独立配置。'}</p></div>
        <span class="status-chip ${state.settings.enabled ? 'active' : ''}">${ico(state.settings.enabled ? 'check_circle' : 'pause_circle')} ${state.settings.enabled ? '程序配置已启用' : state.settings.cliPathMismatch ? 'CLI 路径指向其他版本' : '程序配置未启用'}</span></div>
        <div class="card-body ${state.settings.railCollapsed ? 'rail-collapsed' : ''}">${renderProfileRail()}${resizeHandle('rail', state.settings.railCollapsed ? '向右拖动展开配置列表' : '向左拖动隐藏配置列表')}<div class="editor"><div class="editor-top"><div><h3>${current}</h3><p class="supporting">${state.mode === 'clash' ? 'Clash 订阅' : 'VPS / 节点'} · ${state.selectedId ? '修改后保存' : '填写后保存'}</p></div>
          <div class="editor-actions"><md-text-button data-action="export-profile">${ico('download', 'icon')}导出</md-text-button>
            <md-text-button data-action="delete-profile" ${state.selectedId ? '' : 'disabled'}>${ico('delete', 'icon')}删除</md-text-button></div></div>
          ${editorContent}</div></div></section>
      ${panelOutside ? resizeHandle('dock', '拖动调整停靠面板大小') : ''}${isClash ? renderLayoutDropZones() : ''}
    </div>
    <div class="installation-options"><md-outlined-select id="installation-mode" label="代理启动方式" menu-positioning="fixed">
      ${option('service', '1. 安装 Windows 后台服务（推荐）', state.settings.installationMode === 'service')}
      ${option('desktop', '2. 不安装服务，由桌面启动转发', state.settings.installationMode === 'desktop')}
      </md-outlined-select><p class="supporting">服务模式在桌面启动前就准备好；不安装服务时，每次启动需要允许管理员授权。保存前请先完全退出桌面。</p></div>
    <div class="bottom-actions"><md-filled-button data-action="save-profile">${ico('add', 'icon')}保存并配置</md-filled-button>
      <md-filled-button data-action="disable-proxy">${ico('power_settings_new', 'icon')}停用代理并恢复官方版</md-filled-button></div>
  </div></main>`;
}
function dialogMarkup() {
  return `<md-dialog id="confirm-dialog"><div slot="headline" id="confirm-headline"></div><div slot="content" id="confirm-content"></div>
    <div slot="actions"><md-text-button id="confirm-cancel">取消</md-text-button><md-filled-button id="confirm-accept">继续</md-filled-button></div></md-dialog>
    <md-dialog id="settings-dialog"><div slot="headline" class="settings-heading">${ico('tune')}<span>工作区设置<small>外观、布局与桌面文件</small></span></div><div slot="content" class="settings-grid">
      <section class="settings-section"><h3>外观</h3><md-outlined-select id="theme-choice" label="外观模式" menu-positioning="fixed">
        ${option('system', '跟随系统', state.settings.theme === 'system')}${option('light', '浅色', state.settings.theme === 'light')}${option('dark', '深色', state.settings.theme === 'dark')}
      </md-outlined-select>
      <md-outlined-select id="accent-choice" label="配色来源" menu-positioning="fixed">
        ${option('auto', '设备强调色优先', state.settings.accent === 'auto')}${option('purple', 'Purple 备用主题', state.settings.accent === 'purple')}
      </md-outlined-select>
      <p class="supporting">设备未提供可读取的强调色时，自动使用指定的 Purple 浅色和深色方案。</p>
      </section><section class="settings-section"><h3>桌面文件</h3><p class="settings-path">${esc(state.settings.desktopPath || '尚未选择')}</p><md-outlined-button data-action="edit-desktop">${ico('folder_open', 'icon')}更改桌面文件</md-outlined-button></section>
      <section class="settings-section"><h3>布局</h3><p class="supporting">拖动分区边缘把手调整大小，比例自动保存。</p><md-outlined-button data-action="reset-layout">${ico('restart_alt', 'icon')}恢复默认布局</md-outlined-button></section>
      <section class="settings-section danger"><h3>卸载</h3><p class="supporting">停止并移除 Windows 后台服务，删除本程序安装的运行时和本地代理配置。官方桌面和配置器本身不会删除。</p><md-outlined-button data-action="uninstall-proxy">${ico('delete_forever', 'icon')}卸载专属代理</md-outlined-button></section>
    </div><div slot="actions" class="settings-actions"><md-text-button data-action="show-licenses">许可证显示</md-text-button><md-text-button id="settings-close">完成</md-text-button></div></md-dialog>
    <md-dialog id="license-dialog"><div slot="headline">许可证</div><div slot="content" class="license-content"></div>
      <div slot="actions"><md-text-button data-action="close-licenses">返回设置</md-text-button></div></md-dialog>`;
}
function render() {
  document.querySelector('.toast')?.remove();
  root.innerHTML = (state.screen === 'loading' ? renderLoading() : state.screen === 'desktop' ? renderGate() : renderMain()) + dialogMarkup();
  applyLayoutSizes();
}

function updateExitIpCard() {
  const card = root.querySelector('.exit-ip-card');
  if (!card) return;
  const focusedAction = card.contains(document.activeElement) ? document.activeElement.dataset.action : null;
  card.outerHTML = renderExitIp();
  if (focusedAction) root.querySelector(`.exit-ip-card [data-action="${focusedAction}"]`)?.focus();
}

let exitIpRequest = 0;
function resetExitIp() {
  exitIpRequest++;
  Object.assign(state.exitIp, { value: null, loading: false, error: '', checkedAt: null });
  updateExitIpCard();
}

async function checkExitIp() {
  if (state.exitIp.loading) return;
  syncFormState();
  const profile = structuredClone(state.draft);
  const requestId = ++exitIpRequest;
  state.exitIp.loading = true;
  state.exitIp.error = '';
  updateExitIpCard();
  let timeout;
  try {
    const bridge = window.codexProxy;
    const query = bridge?.getNodeExitIpv4;
    if (typeof query !== 'function') throw new Error('节点检测只能在桌面程序里使用。');
    const result = await Promise.race([
      query.call(bridge, profile),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('查询超时，请重试')), 60000); }),
    ]);
    if (requestId !== exitIpRequest) return;
    const ip = String(typeof result === 'string' ? result : result?.ip || '').trim();
    const parts = typeof ip === 'string' ? ip.split('.') : [];
    if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
      throw new Error('查询结果不是有效的 IP 地址');
    }
    state.exitIp.value = ip;
    state.exitIp.checkedAt = Date.now();
  } catch (error) {
    if (requestId === exitIpRequest) state.exitIp.error = error instanceof Error ? error.message : '无法获取节点出口 IP';
  } finally {
    clearTimeout(timeout);
    if (requestId === exitIpRequest) {
      state.exitIp.loading = false;
      updateExitIpCard();
    }
  }
}

function showConfirm(title, message, onAccept) {
  const dialog = document.querySelector('#confirm-dialog');
  document.querySelector('#confirm-headline').textContent = title;
  document.querySelector('#confirm-content').textContent = message;
  document.querySelector('#confirm-cancel').onclick = () => dialog.close();
  document.querySelector('#confirm-accept').onclick = async () => { dialog.close(); try { await onAccept(); } catch (error) { fail(error); } };
  dialog.show();
}
function chooseMode(kind) {
  if (!modeLabels[kind]) return;
  resetExitIp();
  state.mode = kind;
  state.selectedId = null;
  state.search = '';
  state.draft = freshDraft(kind);
  state.showSecret = false;
  render();
}
function selectProfile(profileId) {
  const profile = state.profiles.find(p => p.id === profileId);
  if (!profile) return;
  resetExitIp();
  state.selectedId = profile.id;
  state.mode = profile.kind;
  state.draft = structuredClone(profile);
  state.showSecret = false;
  render();
}
function nodeKey(node) { return `${node.type}|${node.name}|${node.server}|${node.port}`; }
function normalizeNode(raw) {
  const type = String(raw?.type || '').toLowerCase();
  const name = String(raw?.name || '').trim();
  const server = String(raw?.server || '').trim();
  const port = Number(raw?.port);
  if (!['trojan', 'vless', 'vmess', 'ss', 'shadowsocks', 'ssr', 'hysteria', 'hysteria2', 'tuic', 'snell', 'socks5', 'http'].includes(type) || !name || !server || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  const node = { ...raw, type: type === 'shadowsocks' ? 'ss' : type, name, server, port };
  node.id = raw.id || nodeKey(node);
  return node;
}
function decodeBase64(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  return decodeURIComponent(Array.from(atob(normalized), c => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''));
}
function parseShare(line) {
  try {
    if (line.startsWith('vmess://')) {
      const raw = JSON.parse(decodeBase64(line.slice(8)));
      return normalizeNode({ name: raw.ps || raw.add, type: 'vmess', server: raw.add, port: Number(raw.port), uuid: raw.id,
        network: raw.net || 'tcp', tls: raw.tls === 'tls', 'ws-opts': { path: raw.path || '/', headers: { Host: raw.host || raw.add } } });
    }
    if (line.startsWith('ss://')) {
      let body = line.slice(5); const hash = body.indexOf('#');
      const name = hash >= 0 ? decodeURIComponent(body.slice(hash + 1)) : 'Shadowsocks 节点';
      if (hash >= 0) body = body.slice(0, hash);
      const query = body.indexOf('?'); if (query >= 0) body = body.slice(0, query);
      if (!body.includes('@')) body = decodeBase64(body);
      const [userInfo, address] = body.split('@');
      const credential = userInfo.includes(':') ? userInfo : decodeBase64(userInfo);
      const colon = address.lastIndexOf(':');
      return normalizeNode({ name, type: 'ss', server: address.slice(0, colon), port: Number(address.slice(colon + 1)),
        cipher: credential.slice(0, credential.indexOf(':')), password: credential.slice(credential.indexOf(':') + 1) });
    }
    const url = new URL(line);
    if (!['trojan:', 'vless:'].includes(url.protocol)) return null;
    return normalizeNode({ name: decodeURIComponent(url.hash.slice(1)) || url.hostname, type: url.protocol.slice(0, -1),
      server: url.hostname, port: Number(url.port), password: url.protocol === 'trojan:' ? decodeURIComponent(url.username) : undefined,
      uuid: url.protocol === 'vless:' ? decodeURIComponent(url.username) : undefined,
      sni: url.searchParams.get('sni') || url.searchParams.get('peer') || url.hostname,
      network: url.searchParams.get('type') || 'tcp', tls: true,
      'ws-opts': { path: url.searchParams.get('path') || '/', headers: { Host: url.searchParams.get('host') || url.hostname } },
      'reality-opts': { 'public-key': url.searchParams.get('pbk') || '', 'short-id': url.searchParams.get('sid') || '' } });
  } catch { return null; }
}
function parseNodes(text) {
  let raw;
  try { raw = YAML.parse(text); } catch { raw = null; }
  const candidates = Array.isArray(raw) ? raw : Array.isArray(raw?.proxies) ? raw.proxies : Array.isArray(raw?.nodes) ? raw.nodes : [];
  let nodes = candidates.map(normalizeNode).filter(Boolean);
  if (!nodes.length) nodes = text.split(/\r?\n/).map(s => parseShare(s.trim())).filter(Boolean);
  const seen = new Set();
  nodes = nodes.filter(node => !seen.has(node.id) && seen.add(node.id));
  if (!nodes.length) throw new Error('没有找到支持的节点。请导入含 proxies 的 Clash 文件，或常见节点分享链接。');
  return nodes;
}
function setImportedNodes(nodes, source) {
  resetExitIp();
  const previous = state.draft.selectedNodeId;
  state.draft.nodes = nodes;
  state.draft.source = source;
  state.draft.fetchedUrl = source === 'subscription' ? state.draft.url.trim() : '';
  state.draft.selectedNodeId = nodes.some(n => n.id === previous) ? previous : nodes.length === 1 ? nodes[0].id : '';
  render();
  toast(`已读取 ${nodes.length} 个节点${nodes.length > 1 ? '，请选择一个后保存' : ''}。`);
}
async function fetchNodes() {
  syncFormState();
  const text = state.draft.url.trim();
  let url;
  try { url = new URL(text); } catch { throw new Error('请输入有效的 HTTPS 订阅链接。'); }
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('请输入不含用户名密码的 HTTPS 订阅链接。');
  if (text.length > 8192) throw new Error('订阅链接过长。');
  state.screen = 'loading'; render();
  if (window.codexProxy?.native) {
    try {
      const nodes = await window.codexProxy.request('fetchNodes', text);
      state.screen = 'main';
      setImportedNodes(nodes.map(normalizeNode).filter(Boolean), 'subscription');
    } catch (error) { state.screen = 'main'; render(); throw error; }
    return;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch(url, { signal: controller.signal, credentials: 'omit' });
    if (!response.ok) throw new Error(`订阅服务器返回 HTTP ${response.status}。`);
    if (Number(response.headers.get('content-length')) > 4 * 1024 * 1024) throw new Error('订阅文件超过 4 MB。');
    const body = await response.text();
    if (new Blob([body]).size > 4 * 1024 * 1024) throw new Error('订阅文件超过 4 MB。');
    state.screen = 'main';
    setImportedNodes(parseNodes(body), 'subscription');
  } catch (error) {
    state.screen = 'main'; render();
    if (error.name === 'AbortError') throw new Error('下载超时。可尝试导入已下载的 Clash 文件。');
    if (error instanceof TypeError) throw new Error('订阅下载失败，请检查链接或导入 Clash 文件。');
    throw error;
  } finally { clearTimeout(timer); state.screen = 'main'; }
}
function validateDraft() {
  const draft = state.draft;
  if (!draft.name.trim()) throw new Error('请填写配置名称。');
  if (draft.kind === 'clash') {
    if (draft.url.trim()) {
      let url; try { url = new URL(draft.url.trim()); } catch { throw new Error('订阅链接格式不正确。'); }
      if (url.protocol !== 'https:' || url.username || url.password) throw new Error('订阅链接须为不含用户名密码的 HTTPS 地址。');
    }
    if (!draft.nodes?.length) throw new Error('请先获取订阅，或导入 Clash 文件 / 剪贴板节点。');
    if (!draft.nodes.some(node => node.id === draft.selectedNodeId)) throw new Error('请选择一个以后使用的节点。');
    if (draft.source === 'subscription' && !draft.url.trim()) throw new Error('当前节点来自订阅，请保留对应的订阅链接。');
    if (draft.source === 'subscription' && draft.fetchedUrl && draft.fetchedUrl !== draft.url.trim())
      throw new Error('订阅链接已修改，请先刷新节点。');
  } else {
    if (!draft.server.trim() || /\s/.test(draft.server)) throw new Error('请输入有效的服务器地址。');
    const port = Number(draft.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('端口应为 1 到 65535 之间的整数。');
    if (!draft.credential.trim()) throw new Error('请填写密码或 UUID。');
    if (['vless-ws', 'vless-reality', 'vmess-ws'].includes(draft.protocol) && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(draft.credential.trim())) throw new Error('UUID 格式不正确。');
    if (draft.protocol === 'vless-reality' && !draft.publicKey.trim()) throw new Error('Reality 节点需要公钥。');
    if (draft.protocol === 'ss' && !draft.cipher.trim()) throw new Error('请选择 SS 加密方式。');
    if (['trojan-ws', 'vless-ws', 'vmess-ws'].includes(draft.protocol) && !draft.path.startsWith('/')) throw new Error('WS 路径须以 / 开头。');
  }
}
function syncFormState() {
  document.querySelectorAll('[data-field]').forEach(element => {
    const key = element.dataset.field;
    if (!key) return;
    const value = element.value ?? '';
    if (key === 'desktopPath') { state.settings.desktopPath = String(value); state.settings.desktopSource = 'manual'; }
    else if (key in state.draft) state.draft[key] = String(value);
  });
  const checkedNode = [...document.querySelectorAll('md-radio[name="node"]')].find(node => node.checked);
  if (checkedNode) state.draft.selectedNodeId = checkedNode.value;
}
async function saveProfile() {
  syncFormState();
  validateDraft();
  const now = Date.now();
  const old = state.profiles.find(p => p.id === state.draft.id);
  const profile = { ...structuredClone(state.draft), id: old?.id || id(),
    name: state.draft.name.trim(), createdAt: old?.createdAt || now, updatedAt: now };
  await withOperation('正在保存并配置…', async () => {
    const result = window.codexProxy?.native
      ? await window.codexProxy.request('applyProfile', { profile, desktopPath: state.settings.desktopPath, installationMode: state.settings.installationMode }) : null;
    const index = state.profiles.findIndex(p => p.id === profile.id);
    if (index < 0) state.profiles.unshift(profile); else state.profiles[index] = profile;
    state.profiles.sort((a, b) => b.updatedAt - a.updatedAt);
    state.selectedId = profile.id;
    state.draft = structuredClone(profile);
    state.settings.enabled = true;
    state.settings.cliPathMismatch = false;
    state.settings.activeProfileId = profile.id;
    await Promise.all([persistProfile(profile), persistSettings()]);
    render();
    toast(result || '配置已保存。');
  });
}
async function deleteSelected() {
  const profileId = state.selectedId;
  if (!profileId) return;
  showConfirm('删除配置？', '删除后无法恢复。', async () => {
    if (state.settings.activeProfileId === profileId && window.codexProxy?.native)
      await window.codexProxy.request('disableProxy');
    state.profiles = state.profiles.filter(p => p.id !== profileId);
    if (state.settings.activeProfileId === profileId) {
      state.settings.activeProfileId = null;
      state.settings.enabled = false;
      await persistSettings();
    }
    await removeProfile(profileId);
    state.selectedId = null;
    state.draft = freshDraft(state.mode);
    render(); toast('配置已删除。');
  });
}
async function exportSelected() {
  const profile = state.selectedId ? state.profiles.find(p => p.id === state.selectedId) : null;
  if (!profile) throw new Error('请先保存配置，再导出。');
  await withOperation('正在打开导出窗口…', async () => {
    if (window.codexProxy?.native) {
      if (await window.codexProxy.request('exportProfile', profile)) toast('配置文件已导出。');
      return;
    }
    const blob = new Blob([JSON.stringify(profile, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `codex-proxy-${profile.kind}-${profile.name.replace(/[^\w\u4e00-\u9fa5-]/g, '_')}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast('配置文件已导出。');
  });
}
async function enterMain() {
  syncFormState();
  const path = state.settings.desktopPath.trim();
  if (!/(^|[\\/])ChatGPT\.exe$/i.test(path)) throw new Error('请选择 ChatGPT.exe，或点击“自动定位”后再进入主界面。');
  if (window.codexProxy?.native) await window.codexProxy.request('verifyDesktop', path);
  state.settings.desktopPath = path;
  await persistSettings();
  navigate('main');
}

function eventControl(event) {
  const path = event.composedPath?.() || [];
  return path.find(node => node && (node.dataset?.field || node.id === 'profile-search' || node.id === 'desktop-picker' || node.id === 'clash-picker' || node.id === 'theme-choice' || node.id === 'accent-choice')) || event.target;
}

root.addEventListener('click', async event => {
  const target = event.target.closest?.('[data-action]');
  if (!target) return;
  if (state.busy) return;
  const action = target.dataset.action;
  try {
    syncFormState();
    if (action === 'reset-layout') {
      syncFormState(); Object.assign(state.settings, {layoutPosition:'editor', railRatio:24, dockRatio:48, nodeHeight:200, sourceCollapsed:false, railCollapsed:false});
      await persistSettings(); render(); document.querySelector('#settings-dialog').show();
    } else if (action === 'toggle-exit-ip') {
      state.exitIp.visible = !state.exitIp.visible;
      updateExitIpCard();
      if (state.exitIp.visible && !state.exitIp.value) await checkExitIp();
    } else if (action === 'refresh-exit-ip') await checkExitIp();
    else if (action === 'show-licenses') {
      document.querySelector('#settings-dialog').close();
      const dialog = document.querySelector('#license-dialog');
      dialog.querySelector('.license-content').textContent = licenseText;
      dialog.show();
    } else if (action === 'close-licenses') {
      document.querySelector('#license-dialog').close();
      document.querySelector('#settings-dialog').show();
    } else if (action === 'set-mode') chooseMode(target.dataset.mode);
    else if (action === 'theme-cycle') {
      state.settings.theme = state.settings.theme === 'system' ? 'dark' : state.settings.theme === 'dark' ? 'light' : 'system';
      await persistSettings(); applyColors(); render();
    } else if (action === 'settings') document.querySelector('#settings-dialog').show();
    else if (action === 'edit-desktop') { document.querySelector('#settings-dialog').close(); navigate('desktop'); }
    else if (action === 'choose-desktop') {
      if (window.codexProxy?.native) {
        const path = await window.codexProxy.request('chooseDesktop');
        if (path) { state.settings.desktopPath = path; state.settings.desktopSource = 'picker'; render(); }
      } else document.querySelector('#desktop-picker').click();
    }
    else if (action === 'locate-desktop') await withOperation('正在查找官方桌面…', async () => {
      if (!window.codexProxy?.native) throw new Error('自动定位仅在桌面配置器中可用，请选择 ChatGPT.exe。');
      const path = await window.codexProxy.request('locateDesktop');
      if (!path) throw new Error('没有找到官方桌面，请安装后重试或选择 ChatGPT.exe。');
      state.settings.desktopPath = path;
      state.settings.desktopSource = 'auto';
      await persistSettings();
      render();
      toast('已找到官方桌面。');
    });
    else if (action === 'enter-main') await enterMain();
    else if (action === 'new-profile') { resetExitIp(); state.selectedId = null; state.draft = freshDraft(state.mode); state.showSecret = false; render(); }
    else if (action === 'select-profile') selectProfile(target.dataset.id);
    else if (action === 'show-secret') { state.showSecret = !state.showSecret; render(); }
    else if (action === 'fetch-nodes') await fetchNodes();
    else if (action === 'import-file') {
      if (window.codexProxy?.native) {
        const nodes = await window.codexProxy.request('importFile');
        if (nodes) setImportedNodes(nodes.map(normalizeNode).filter(Boolean), 'file');
      } else document.querySelector('#clash-picker').click();
    }
    else if (action === 'import-clipboard') {
      if (window.codexProxy?.native) {
        const nodes = await window.codexProxy.request('importClipboard');
        setImportedNodes(nodes.map(normalizeNode).filter(Boolean), 'clipboard');
      } else setImportedNodes(parseNodes(await navigator.clipboard.readText()), 'clipboard');
    } else if (action === 'save-profile') await saveProfile();
    else if (action === 'delete-profile') await deleteSelected();
    else if (action === 'export-profile') await exportSelected();
    else if (action === 'disable-proxy') showConfirm('停用代理并恢复官方版 CLI？', '确认停用当前代理配置？', async () => {
      if (window.codexProxy?.native) await window.codexProxy.request('disableProxy');
      state.settings.enabled = false; state.settings.cliPathMismatch = false; state.settings.activeProfileId = null; await persistSettings(); render(); toast('代理配置已停用。');
    });
    else if (action === 'uninstall-proxy') showConfirm('卸载专属代理？', '这将停止并移除 Windows 服务，删除专属运行时和本地代理配置。官方桌面和配置器本身不会删除。', async () => {
      await withOperation('正在卸载专属代理…', async () => {
        if (!window.codexProxy?.native) throw new Error('卸载仅在桌面配置器中可用。');
        await window.codexProxy.request('uninstallProxy');
        state.profiles = [];
        state.selectedId = null;
        state.mode = 'clash';
        state.draft = freshDraft('clash');
        state.settings = { installationMode: 'service', desktopPath: '', desktopSource: '', enabled: false, cliPathMismatch: false,
          activeProfileId: null, theme: 'system', accent: 'auto', layoutPosition: 'editor', railRatio: 24, dockRatio: 48, nodeHeight: 200, sourceCollapsed: false, railCollapsed: false };
        document.querySelector('#settings-dialog')?.close();
        render();
        toast('专属代理已完全卸载。');
      });
    });
  } catch (error) { fail(error); }
});

function layoutZoneAtPoint(x, y) {
  return document.elementFromPoint(x, y)?.closest?.('[data-layout-slot]') || null;
}
function clearLayoutDragVisual() {
  document.querySelector('[data-layout-canvas]')?.classList.remove('is-dragging');
  document.querySelectorAll('.layout-drop-zone.drag-over').forEach(item => item.classList.remove('drag-over'));
}
function markLayoutZone(zone) {
  document.querySelectorAll('.layout-drop-zone.drag-over').forEach(item => item.classList.remove('drag-over'));
  zone?.classList.add('drag-over');
}
async function finishLayoutDrag(position) {
  state.draggingLayout = false;
  state.layoutPointerId = null;
  clearLayoutDragVisual();
  if (!layoutPositionLabels[position]) return;
  state.settings.layoutPosition = position;
  await persistSettings();
  render();
  toast(`订阅与节点面板已移动到${layoutPositionLabels[position]}。`);
}

root.addEventListener('pointerdown', event => {
  const handle = event.target.closest?.('[data-layout-panel]');
  if (!handle) return;
  event.preventDefault();
  syncFormState();
  state.draggingLayout = true;
  state.layoutPointerId = event.pointerId;
  handle.setPointerCapture?.(event.pointerId);
  document.querySelector('[data-layout-canvas]')?.classList.add('is-dragging');
});

root.addEventListener('pointermove', event => {
  if (!state.draggingLayout || event.pointerId !== state.layoutPointerId) return;
  event.preventDefault();
  markLayoutZone(layoutZoneAtPoint(event.clientX, event.clientY));
});

root.addEventListener('pointerup', async event => {
  if (!state.draggingLayout || event.pointerId !== state.layoutPointerId) return;
  event.preventDefault();
  const zone = layoutZoneAtPoint(event.clientX, event.clientY);
  await finishLayoutDrag(zone?.dataset.layoutSlot);
});

root.addEventListener('pointercancel', event => {
  if (!state.draggingLayout || event.pointerId !== state.layoutPointerId) return;
  state.draggingLayout = false;
  state.layoutPointerId = null;
  clearLayoutDragVisual();
});

root.addEventListener('input', event => {
  const element = eventControl(event);
  if (element.id === 'profile-search') {
    state.search = element.value || '';
    const query = state.search.trim().toLocaleLowerCase();
    document.querySelectorAll('.profile-item').forEach(item => { item.hidden = !item.textContent.toLocaleLowerCase().includes(query); });
    return;
  }
  const field = element.dataset?.field;
  if (!field) return;
  if (field === 'desktopPath') element.error = false;
  if (field === 'desktopPath') { state.settings.desktopPath = element.value || ''; state.settings.desktopSource = 'manual'; }
  else if (field in state.draft) { state.draft[field] = element.value || ''; resetExitIp(); }
}, true);

root.addEventListener('change', async event => {
  const element = eventControl(event);
  try {
    if (element.id === 'desktop-picker') {
      const file = element.files?.[0]; if (!file) return;
      if (file.name.toLowerCase() !== 'chatgpt.exe') throw new Error('请选择名为 ChatGPT.exe 的桌面程序。');
      state.settings.desktopPath = file.name; state.settings.desktopSource = 'picker';
      render(); toast('已选择 ChatGPT.exe。');
    } else if (element.id === 'clash-picker') {
      const file = element.files?.[0]; if (!file) return;
      if (file.size > 4 * 1024 * 1024) throw new Error('配置文件超过 4 MB。');
      setImportedNodes(parseNodes(await file.text()), 'file');
    } else if (element.id === 'installation-mode') {
      state.settings.installationMode = element.value; await persistSettings();
    } else if (element.id === 'theme-choice') {
      state.settings.theme = element.value; await persistSettings(); applyColors(); render(); document.querySelector('#settings-dialog').show();
    } else if (element.id === 'accent-choice') {
      state.settings.accent = element.value; await persistSettings(); applyColors(); render(); document.querySelector('#settings-dialog').show();
    } else if (element.id === 'profile-search') {
      state.search = element.value || '';
    } else if (element.dataset?.field === 'protocol') {
      state.draft.protocol = element.value; render();
    } else if (element.tagName === 'MD-RADIO' && element.name === 'node') {
      state.draft.selectedNodeId = element.value;
      resetExitIp();
      document.querySelectorAll('md-radio[name="node"]').forEach(radio => { radio.checked = radio === element; });
    }
  } catch (error) { fail(error); }
}, true);

root.addEventListener('click', event => {
  if (event.target.id === 'settings-close') document.querySelector('#settings-dialog').close();
});
window.addEventListener('popstate', event => {
  const screen = event.state?.screen;
  state.screen = screen === 'main' && !/(^|[\\/])ChatGPT\.exe$/i.test(state.settings.desktopPath) ? 'desktop' : screen || 'desktop';
  state.reverse = true; render();
});
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (state.settings.theme === 'system') { applyColors(); render(); } });

async function boot() {
  applyColors(); render();
  const minimum = delay(360);
  try { await loadSaved(); } catch (error) { fail(error); }
  await minimum;
  applyColors();
  const active = state.profiles.find(profile => profile.id === state.settings.activeProfileId);
  if (active) {
    state.mode = active.kind;
    state.selectedId = active.id;
    state.draft = structuredClone(active);
  }
  state.screen = /(^|[\\/])ChatGPT\.exe$/i.test(state.settings.desktopPath) ? 'main' : 'desktop';
  history.replaceState({ screen: state.screen }, '', location.href);
  render();
}
boot();
function applyLayoutSizes() {
  const bounded = (value, min, max, fallback) => Math.min(max, Math.max(min, Number(value) || fallback));
  root.style.setProperty('--rail-ratio', bounded(state.settings.railRatio,18,48,24)+'%');
  root.style.setProperty('--dock-ratio', bounded(state.settings.dockRatio,25,70,48)+'%');
  root.style.setProperty('--node-height', bounded(state.settings.nodeHeight,120,600,200)+'px');
  applySourceCollapse();
  applyRailCollapse();
}
function applySourceCollapse() {
  const collapsed = !!state.settings.sourceCollapsed;
  root.querySelector('.workspace')?.classList.toggle('source-collapsed', collapsed);
  const source = root.querySelector('#source-panel');
  source?.toggleAttribute('inert', collapsed);
  if (collapsed) source?.setAttribute('aria-hidden', 'true');
  else source?.removeAttribute('aria-hidden');
  const handle = root.querySelector('.resize-source');
  if (!handle) return;
  const label = collapsed ? '向下拖动展开上方配置区' : '向上拖动收起上方配置区';
  handle.setAttribute('aria-label', label);
  handle.setAttribute('aria-valuenow', collapsed ? '0' : '100');
  handle.title = `${label}（方向键操作，双击展开）`;
  handle.querySelector('.source-handle-copy').textContent = collapsed ? '向下拖动展开上方' : '向上拖动收起上方';
  handle.querySelector('md-icon').textContent = collapsed ? 'keyboard_arrow_down' : 'keyboard_arrow_up';
}
function setSourceCollapsed(value) {
  if (state.settings.sourceCollapsed === value) return;
  state.settings.sourceCollapsed = value;
  applySourceCollapse();
}
function applyRailCollapse() {
  const collapsed = !!state.settings.railCollapsed;
  const stacked = innerWidth <= 900 || (state.mode === 'clash' && state.settings.layoutPosition !== 'editor');
  root.querySelector('.card-body')?.classList.toggle('rail-collapsed', collapsed);
  const rail = root.querySelector('#profile-rail');
  rail?.toggleAttribute('inert', collapsed);
  if (collapsed) rail?.setAttribute('aria-hidden', 'true');
  else rail?.removeAttribute('aria-hidden');
  const handle = root.querySelector('.resize-rail');
  if (!handle) return;
  const label = collapsed
    ? stacked ? '向下拖动展开配置列表' : '向右拖动展开配置列表'
    : stacked ? '向上拖动隐藏配置列表' : '向左拖动隐藏配置列表';
  handle.setAttribute('aria-label', label);
  handle.setAttribute('aria-valuenow', collapsed ? '0' : String(state.settings.railRatio));
  handle.title = `${label}（方向键操作，双击复位）`;
  handle.querySelector('md-icon').textContent = collapsed ? stacked ? 'keyboard_arrow_down' : 'chevron_right' : stacked ? 'keyboard_arrow_up' : 'chevron_left';
}
function setRailCollapsed(value) {
  if (state.settings.railCollapsed === value) return;
  state.settings.railCollapsed = value;
  applyRailCollapse();
}
let resizing = null;
function resizeValue(kind, value) {
  const key = {rail:'railRatio', dock:'dockRatio', nodes:'nodeHeight'}[kind];
  const limits = kind === 'nodes' ? [120,600] : kind === 'rail' ? [18,48] : [25,70];
  state.settings[key] = Math.min(limits[1], Math.max(limits[0], value));
  applyLayoutSizes();
}
root.addEventListener('pointerdown', event => {
  const handle = event.target.closest?.('[data-resize]');
  if (!handle || event.button !== 0) return;
  event.preventDefault();
  const kind = handle.dataset.resize;
  const area = kind === 'rail' ? handle.parentElement : document.querySelector('[data-layout-canvas]');
  resizing = {kind, rect:area.getBoundingClientRect(), handle, id:event.pointerId, startY:event.clientY, height:state.settings.nodeHeight || 200, originalCollapsed:!!state.settings.sourceCollapsed};
  handle.setPointerCapture(event.pointerId);
  handle.classList.add('resizing');
});
root.addEventListener('pointermove', event => {
  if (!resizing || resizing.id !== event.pointerId) return;
  const {kind,rect,startY,height,originalCollapsed} = resizing;
  if (kind === 'source') {
    const delta = event.clientY - startY;
    setSourceCollapsed(delta <= -24 ? true : delta >= 24 ? false : originalCollapsed);
  } else if (kind === 'rail') {
    const stacked = innerWidth <= 900 || (state.mode === 'clash' && state.settings.layoutPosition !== 'editor');
    if (stacked) {
      const delta = event.clientY - startY;
      if (delta <= -24) setRailCollapsed(true);
      else if (delta >= 24) setRailCollapsed(false);
      else setRailCollapsed(originalCollapsed);
    } else {
      const value = (event.clientX - rect.left) / rect.width * 100;
      if (value <= 5) setRailCollapsed(true);
      else { setRailCollapsed(false); resizeValue('rail', value); }
    }
  } else if (kind === 'nodes') resizeValue(kind, height + event.clientY - startY);
  else {
    const position = state.settings.layoutPosition;
    const vertical = kind === 'dock' && (['top','bottom'].includes(position) || innerWidth <= 900);
    let value = vertical ? (event.clientY-rect.top)/rect.height*100 : (event.clientX-rect.left)/rect.width*100;
    if (kind === 'dock' && (position === 'bottom' || (position === 'right' && !vertical))) value = 100-value;
    resizeValue(kind,value);
  }
});
async function stopResize(event) {
  if (!resizing || resizing.id !== event.pointerId) return;
  resizing.handle.classList.remove('resizing'); resizing = null;
  try { await persistSettings(); } catch (error) { fail(error); }
}
root.addEventListener('pointerup', stopResize);
root.addEventListener('pointercancel', stopResize);
root.addEventListener('dblclick', async event => {
  const handle = event.target.closest?.('[data-resize]');
  if (!handle) return;
  if (handle.dataset.resize === 'source') setSourceCollapsed(false);
  else if (handle.dataset.resize === 'rail') {
    if (state.settings.railCollapsed) setRailCollapsed(false);
    else resizeValue('rail', 24);
  } else resizeValue(handle.dataset.resize, {dock:48,nodes:200}[handle.dataset.resize]);
  try { await persistSettings(); } catch (error) { fail(error); }
});
root.addEventListener('keydown', async event => {
  const handle = event.target.closest?.('[data-resize]');
  if (!handle) return;
  if (handle.dataset.resize === 'source') {
    if (!['ArrowUp','ArrowDown','Home','End','Enter',' '].includes(event.key)) return;
    event.preventDefault();
    setSourceCollapsed(['ArrowUp','Home'].includes(event.key) ? true : ['ArrowDown','End'].includes(event.key) ? false : !state.settings.sourceCollapsed);
    try { await persistSettings(); } catch (error) { fail(error); }
    return;
  }
  if (handle.dataset.resize === 'rail') {
    if (!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End','Enter',' '].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Home') setRailCollapsed(true);
    else if (event.key === 'End') setRailCollapsed(false);
    else if (event.key === 'Enter' || event.key === ' ') setRailCollapsed(!state.settings.railCollapsed);
    else if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      if (state.settings.railCollapsed) setRailCollapsed(false);
      else resizeValue('rail', state.settings.railRatio + 2);
    } else if (state.settings.railRatio <= 18 || event.key === 'ArrowUp') setRailCollapsed(true);
    else resizeValue('rail', state.settings.railRatio - 2);
    try { await persistSettings(); } catch (error) { fail(error); }
    return;
  }
  if (!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key)) return;
  event.preventDefault();
  const kind = handle.dataset.resize;
  const key = {rail:'railRatio',dock:'dockRatio',nodes:'nodeHeight'}[kind];
  let delta = ['ArrowLeft','ArrowUp'].includes(event.key) ? -1 : 1;
  if (kind === 'dock' && ['right','bottom'].includes(state.settings.layoutPosition)) delta *= -1;
  resizeValue(kind, state.settings[key] + delta*(kind === 'nodes' ? 16 : 2));
  try { await persistSettings(); } catch (error) { fail(error); }
});
