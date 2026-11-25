package daemon

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"browserforge/internal/common"
	"browserforge/internal/kernel"
	"browserforge/internal/launcher"
	"browserforge/internal/store"
)

const panelCookieName = "bf_panel"

// CreatePanelEnterURL mints a single-use 60-second login ticket URL for opening the local panel from the tray icon.
func (s *Server) CreatePanelEnterURL() (string, error) {
	ticket, err := common.RandomHex(24)
	if err != nil {
		return "", err
	}
	s.panelMu.Lock()
	defer s.panelMu.Unlock()
	now := time.Now()
	for k, exp := range s.panelTickets {
		if now.After(exp) {
			delete(s.panelTickets, k)
		}
	}
	s.panelTickets[ticket] = now.Add(60 * time.Second)
	return fmt.Sprintf("http://127.0.0.1:%d/panel/enter?ticket=%s", s.state.Port, ticket), nil
}

func (s *Server) setPanelSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
}

func (s *Server) handlePanelEnter(w http.ResponseWriter, r *http.Request) {
	s.setPanelSecurityHeaders(w)
	ticket := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if ticket == "" {
		writeErr(w, http.StatusUnauthorized, "missing ticket")
		return
	}
	s.panelMu.Lock()
	exp, ok := s.panelTickets[ticket]
	if ok {
		delete(s.panelTickets, ticket) // single-use burn
	}
	s.panelMu.Unlock()
	if !ok || time.Now().After(exp) {
		writeErr(w, http.StatusUnauthorized, "invalid or expired ticket")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     panelCookieName,
		Value:    s.panelSecret,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/panel", http.StatusFound)
}

func (s *Server) hasValidPanelCookie(r *http.Request) bool {
	c, err := r.Cookie(panelCookieName)
	if err != nil || c == nil {
		return false
	}
	return len(c.Value) == len(s.panelSecret) &&
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.panelSecret)) == 1
}

func (s *Server) withPanelAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.setPanelSecurityHeaders(w)
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		expectedLoopback := fmt.Sprintf("http://127.0.0.1:%d", s.state.Port)
		expectedLocalhost := fmt.Sprintf("http://localhost:%d", s.state.Port)
		if origin != "" && origin != expectedLoopback && origin != expectedLocalhost {
			writeErr(w, http.StatusForbidden, "cross-origin forbidden")
			return
		}
		if !s.hasValidPanelCookie(r) {
			writeErr(w, http.StatusUnauthorized, "open panel from BrowserForge tray icon")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-BF-Panel") != "1" {
			writeErr(w, http.StatusForbidden, "missing X-BF-Panel header")
			return
		}
		next(w, r)
	}
}

func (s *Server) handlePanelPage(w http.ResponseWriter, r *http.Request) {
	s.setPanelSecurityHeaders(w)
	if !s.hasValidPanelCookie(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `<!doctype html><html><body style="font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:40px"><h2>BrowserForge Panel</h2><p>Please open this panel from the BrowserForge system tray icon.</p></body></html>`)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, panelHTML)
}

func (s *Server) handlePanelStatus(w http.ResponseWriter, r *http.Request) {
	cfg, _ := s.st.LoadSettings()
	k := kernel.Resolve(cfg.KernelExe)
	profiles, _ := s.st.ListProfiles()
	proxies, _ := s.st.ListProxies()

	proxyMap := map[string]store.PublicProxy{}
	pubProxies := make([]store.PublicProxy, 0, len(proxies))
	for _, p := range proxies {
		pub := p.Public()
		proxyMap[p.ID] = pub
		pubProxies = append(pubProxies, pub)
	}

	type profView struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Template   string `json:"template"`
		Timezone   string `json:"timezone"`
		Languages  string `json:"languages"`
		ProxyName  string `json:"proxy_name"`
		Running    bool   `json:"running"`
		BrowserPID int    `json:"browser_pid,omitempty"`
		ProxyPort  int    `json:"proxy_port,omitempty"`
		DebugPort  int    `json:"debug_port,omitempty"`
	}
	var profViews []profView
	activeCount := 0
	for _, p := range profiles {
		pv := profView{
			ID:        p.ID,
			Name:      p.Name,
			Template:  p.Template,
			Timezone:  p.Timezone,
			Languages: strings.Join(p.Languages, ", "),
		}
		if pr, ok := proxyMap[p.ProxyID]; ok {
			pv.ProxyName = fmt.Sprintf("%s (%s)", pr.Name, pr.ExitCountry)
		}
		if rt, _ := s.st.LoadRuntime(p.ID); rt != nil && kernel.IsProcessAlive(rt.BrowserPID) {
			pv.Running = true
			pv.BrowserPID = rt.BrowserPID
			pv.ProxyPort = rt.ProxyPort
			pv.DebugPort = rt.DebugPort
			activeCount++
		}
		profViews = append(profViews, pv)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"daemon": map[string]any{
			"pid":          s.state.PID,
			"port":         s.state.Port,
			"version":      s.state.Version,
			"started_at":   s.state.StartedAt,
			"data_dir":     s.st.DataDir,
			"active_count": activeCount,
		},
		"kernel":   k,
		"profiles": profViews,
		"proxies":  pubProxies,
	})
}

func (s *Server) handlePanelStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Profile  string `json:"profile"`
		StartURL string `json:"start_url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := launcher.StartProfile(s.st, launcher.StartRequest{
		ProfileRef: body.Profile,
		StartURL:   body.StartURL,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res.ViaDaemon = true
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handlePanelStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Profile string `json:"profile"`
		All     bool   `json:"all"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.All {
		n := s.StopAllBrowsers()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stopped": n})
		return
	}
	rec, err := s.st.FindProfile(body.Profile)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err := launcher.StopProfile(s.st, rec.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stopped": rec.ID})
}

// ActiveBrowserCount returns the number of currently alive browser profiles.
func (s *Server) ActiveBrowserCount() int {
	profiles, _ := s.st.ListProfiles()
	n := 0
	for _, p := range profiles {
		if rt, _ := s.st.LoadRuntime(p.ID); rt != nil && kernel.IsProcessAlive(rt.BrowserPID) {
			n++
		}
	}
	return n
}

// StopAllBrowsers stops all running browser instances and returns how many were stopped.
func (s *Server) StopAllBrowsers() int {
	profiles, _ := s.st.ListProfiles()
	n := 0
	for _, p := range profiles {
		if rt, _ := s.st.LoadRuntime(p.ID); rt != nil {
			_ = launcher.StopProfile(s.st, p.ID)
			n++
		}
	}
	return n
}

const panelHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>BrowserForge Status Panel</title>
<style>
  :root { --bg:#0b1120; --card:#111827; --border:#1f2937; --text:#f1f5f9; --muted:#94a3b8; --accent:#10b981; --danger:#ef4444; --btn:#1e293b; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:var(--bg); color:var(--text); padding:24px; }
  .wrap { max-width:980px; margin:0 auto; }
  header { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:20px; }
  .brand { display:flex; align-items:center; gap:10px; font-size:20px; font-weight:700; }
  .dot { width:10px; height:10px; border-radius:50%; background:var(--accent); box-shadow:0 0 10px var(--accent); }
  .meta { color:var(--muted); font-size:13px; margin-top:4px; }
  .actions { display:flex; gap:8px; }
  button { background:var(--btn); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:7px 14px; font-size:13px; cursor:pointer; transition:opacity .15s; }
  button:hover:not(:disabled) { border-color:#475569; }
  button:disabled { opacity:.55; cursor:wait; }
  button.primary { background:#059669; border-color:#059669; }
  button.primary:hover:not(:disabled) { background:#047857; }
  button.danger { background:#7f1d1d; border-color:#991b1b; }
  button.danger:hover:not(:disabled) { background:#991b1b; }
  .toast { position:fixed; right:24px; bottom:24px; background:#1e293b; color:#f8fafc; border:1px solid #334155; border-radius:10px; padding:10px 16px; font-size:13px; box-shadow:0 10px 25px rgba(0,0,0,.45); opacity:0; pointer-events:none; transition:opacity .2s; max-width:420px; z-index:99; }
  .toast.show { opacity:1; }
  .toast.err { border-color:#ef4444; color:#fecaca; }
  .toast.ok { border-color:#10b981; color:#a7f3d0; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin-bottom:20px; }
  .stat { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:14px 16px; }
  .stat .k { color:var(--muted); font-size:12px; }
  .stat .v { font-size:16px; font-weight:600; margin-top:6px; word-break:break-all; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; margin-bottom:18px; }
  .card h3 { margin:0 0 12px 0; font-size:15px; font-weight:600; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:500; }
  .pill { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:500; }
  .pill.on { background:rgba(16,185,129,.18); color:#34d399; }
  .pill.off { background:rgba(148,163,184,.15); color:var(--muted); }
  .mono { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; }
  .msg { font-size:13px; color:#fbbf24; min-height:18px; margin-bottom:10px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <div class="brand"><span class="dot"></span>BrowserForge Foreground Daemon</div>
      <div class="meta" id="meta">Loading...</div>
    </div>
    <div class="actions">
      <button id="btn-refresh">刷新</button>
      <button class="danger" id="btn-stop-all">停止全部浏览器</button>
    </div>
  </header>
  <div id="msg" class="msg"></div>
  <div class="grid">
    <div class="stat"><div class="k">守护进程</div><div class="v mono" id="s-daemon">-</div></div>
    <div class="stat"><div class="k">运行中实例</div><div class="v" id="s-active">-</div></div>
    <div class="stat"><div class="k">默认内核</div><div class="v mono" id="s-kernel">-</div></div>
    <div class="stat"><div class="k">数据目录</div><div class="v mono" id="s-dir">-</div></div>
  </div>
  <div class="card">
    <h3>隔离环境（Profiles）</h3>
    <table>
      <thead><tr><th>名称</th><th>模板 / 时区</th><th>绑定代理</th><th>状态</th><th>PID / CDP / Proxy</th><th>操作</th></tr></thead>
      <tbody id="tb-profiles"><tr><td colspan="6" style="color:#94a3b8">加载中...</td></tr></tbody>
    </table>
  </div>
  <div class="card">
    <h3>加密代理库（Proxies · 密码已脱敏）</h3>
    <table>
      <thead><tr><th>名称</th><th>协议与地址</th><th>出口 IP</th><th>地区 / 时区</th></tr></thead>
      <tbody id="tb-proxies"><tr><td colspan="4" style="color:#94a3b8">加载中...</td></tr></tbody>
    </table>
  </div>
</div>
<div id="toast" class="toast"></div>
<script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let toastTimer = null;
const busyProfiles = new Set();
let lastProfilesKey = '';
let lastProxiesKey = '';

function setMsg(t, kind) {
  document.getElementById('msg').textContent = t || '';
  const el = document.getElementById('toast');
  if (!t) { el.className = 'toast'; return; }
  el.textContent = t;
  el.className = 'toast show' + (kind === 'err' ? ' err' : kind === 'ok' ? ' ok' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 4500);
}

async function api(path, body) {
  const opts = body
    ? { method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json','X-BF-Panel':'1'}, body:JSON.stringify(body) }
    : { credentials:'same-origin' };
  const r = await fetch(path, opts);
  const text = await r.text();
  let d = {};
  try { d = JSON.parse(text); } catch (_) { throw new Error('HTTP ' + r.status + ': ' + text.slice(0, 120)); }
  if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

async function startProf(name, btn) {
  if (busyProfiles.has(name)) return;
  busyProfiles.add(name);
  if (btn) { btn.disabled = true; btn.textContent = '启动中...'; }
  setMsg('正在启动 ' + name + ' ...');
  try {
    await api('/panel/api/start', { profile: name });
    setMsg('已启动 ' + name, 'ok');
  } catch (e) {
    setMsg('启动失败 (' + name + '): ' + e.message, 'err');
  } finally {
    busyProfiles.delete(name);
    lastProfilesKey = '';
    await load();
  }
}

async function stopProf(name, btn) {
  if (busyProfiles.has(name)) return;
  busyProfiles.add(name);
  if (btn) { btn.disabled = true; btn.textContent = '停止中...'; }
  setMsg('正在停止 ' + name + ' ...');
  try {
    await api('/panel/api/stop', { profile: name });
    setMsg('已停止 ' + name, 'ok');
  } catch (e) {
    setMsg('停止失败 (' + name + '): ' + e.message, 'err');
  } finally {
    busyProfiles.delete(name);
    lastProfilesKey = '';
    await load();
  }
}

async function stopAll() {
  const btn = document.getElementById('btn-stop-all');
  if (btn) btn.disabled = true;
  setMsg('正在停止全部浏览器...');
  try {
    const r = await api('/panel/api/stop', { all: true });
    setMsg('已停止 ' + r.stopped + ' 个实例', 'ok');
  } catch (e) {
    setMsg('操作失败: ' + e.message, 'err');
  } finally {
    if (btn) btn.disabled = false;
    lastProfilesKey = '';
    await load();
  }
}

document.getElementById('btn-refresh').addEventListener('click', () => {
  lastProfilesKey = '';
  lastProxiesKey = '';
  load();
});
document.getElementById('btn-stop-all').addEventListener('click', stopAll);
document.getElementById('tb-profiles').addEventListener('click', (ev) => {
  const btn = ev.target.closest('button[data-action]');
  if (!btn || btn.disabled) return;
  const act = btn.getAttribute('data-action');
  const name = btn.getAttribute('data-profile');
  if (!name) return;
  if (act === 'start') startProf(name, btn);
  else if (act === 'stop') stopProf(name, btn);
});

async function load() {
  try {
    const d = await api('/panel/api/status');
    document.getElementById('meta').textContent = 'v' + d.daemon.version + ' · 127.0.0.1:' + d.daemon.port + ' · Started ' + d.daemon.started_at;
    document.getElementById('s-daemon').textContent = 'PID ' + d.daemon.pid + ' (:' + d.daemon.port + ')';
    document.getElementById('s-active').textContent = d.daemon.active_count + ' / ' + (d.profiles ? d.profiles.length : 0);
    document.getElementById('s-kernel').textContent = d.kernel ? (d.kernel.kind + ' v' + d.kernel.version) : '未配置';
    document.getElementById('s-dir').textContent = d.daemon.data_dir;

    const pKey = JSON.stringify(d.profiles || []) + '|' + Array.from(busyProfiles).join(',');
    if (pKey !== lastProfilesKey && busyProfiles.size === 0) {
      lastProfilesKey = pKey;
      const pRows = (d.profiles || []).map(p => '<tr>' +
        '<td><strong>' + esc(p.name) + '</strong></td>' +
        '<td>' + esc(p.template) + '<div class="meta">' + esc(p.timezone) + '</div></td>' +
        '<td>' + esc(p.proxy_name || '直连') + '</td>' +
        '<td><span class="pill ' + (p.running ? 'on">运行中' : 'off">已停止') + '</span></td>' +
        '<td class="mono">' + (p.running ? ('PID ' + p.browser_pid + ' · CDP :' + p.debug_port + (p.proxy_port ? ' · Proxy :' + p.proxy_port : '')) : '-') + '</td>' +
        '<td>' + (p.running
          ? '<button class="danger" data-action="stop" data-profile="' + esc(p.name) + '">停止</button>'
          : '<button class="primary" data-action="start" data-profile="' + esc(p.name) + '">启动</button>') + '</td>' +
      '</tr>').join('');
      document.getElementById('tb-profiles').innerHTML = pRows || '<tr><td colspan="6" style="color:#94a3b8">暂无环境</td></tr>';
    }

    const xKey = JSON.stringify(d.proxies || []);
    if (xKey !== lastProxiesKey) {
      lastProxiesKey = xKey;
      const xRows = (d.proxies || []).map(x => '<tr>' +
        '<td>' + esc(x.name) + '</td>' +
        '<td class="mono">' + esc(x.scheme + '://' + x.host + ':' + x.port) + '</td>' +
        '<td class="mono">' + esc(x.exit_ip || '-') + '</td>' +
        '<td>' + esc((x.exit_country || '-') + ' / ' + (x.exit_timezone || '-')) + '</td>' +
      '</tr>').join('');
      document.getElementById('tb-proxies').innerHTML = xRows || '<tr><td colspan="4" style="color:#94a3b8">暂无代理</td></tr>';
    }
  } catch (e) {
    setMsg('守护进程连接异常: ' + e.message, 'err');
  }
}
load();
setInterval(load, 3000);
</script>
</body>
</html>`
