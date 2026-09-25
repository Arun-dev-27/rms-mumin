import { config } from './config';
import type { BrowserState } from './bu.service';

const HANDOFF_PATH_OPTIONS = ['/events/123', '/events/123/details', '/bookings/ABC', '/bookings/ABC/summary', '/dashboard', '/admin/users'];

export function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

const time = (iso: string) => new Date(iso).toLocaleTimeString();

const CSS = `
:root{--teal:#1c5a5c;--gold:#8a6a45;--red:#9b2c1f;--cream:#fbf9f5;--ink:#1d2b33;--muted:#5b6770;--line:#e4ded3;--bad:#b91c1c;--card:#fff}
*{box-sizing:border-box}body{margin:0;font-family:Mulish,system-ui,sans-serif;background:var(--cream);color:var(--ink)}
header{background:linear-gradient(90deg,#10232a,#215f60);color:#fff;padding:16px 24px;font-size:20px;font-family:Marcellus,serif}
header small{opacity:.7;font-family:Mulish,system-ui,sans-serif;font-size:13px}
main{max-width:820px;margin:24px auto;padding:0 16px}
h2{font-family:Marcellus,serif;font-weight:400;color:var(--teal)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.card h3{margin:0;font-size:22px;font-weight:600}.meta{color:var(--muted);font-size:13px;margin:4px 0 12px}
.realm{font-size:12px;font-weight:800;padding:2px 9px;border-radius:999px;margin-left:8px;vertical-align:middle}
.realm.ADMIN{background:#fde68a;color:#78350f}.realm.MUMIN{background:#bbf7d0;color:#14532d}
.btns{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
a.btn,button.btn{border:0;cursor:pointer;font:inherit;font-size:14px;font-weight:700;padding:9px 16px;border-radius:999px;background:var(--teal);color:#fff;text-decoration:none}
a.btn.gold{background:var(--gold)}a.btn.red{background:var(--red)}a.btn.light,button.btn.light{background:#e8efee;color:var(--teal)}
.status{padding:12px 14px;border-radius:10px;font-size:14px;margin-top:10px}
.status.in{background:#f0fdf4;border:1px solid #bbf7d0}.status.out{background:#f8fafc;border:1px dashed var(--line);color:var(--muted)}
.status.err{background:#fef2f2;border:1px solid #fecaca;color:var(--bad)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 10px;font-size:12.5px;margin-top:6px}.kv b{color:var(--muted);font-weight:600}
code,.mono{font-family:Consolas,monospace;font-size:12.5px}
details{margin-top:8px}summary{cursor:pointer;color:var(--teal);font-size:13px;font-weight:700}
pre{background:#f4f1ea;border-radius:8px;padding:10px;font-size:11.5px;overflow:auto;max-height:280px}
.handoff{margin-top:14px;font-size:14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;color:var(--muted)}
.handoff select{font:inherit;font-size:14px;padding:6px 8px;border:1px solid var(--line);border-radius:6px;color:var(--ink);background:#fff}
.bc{margin-top:12px;font-size:13px;color:var(--muted)}
.events{margin:12px 0 0;padding:8px 10px 8px 24px;background:#f8fafc;border-radius:8px;font-size:12.5px}.events li{margin:3px 0}.events li.no{color:var(--bad)}
.muted{color:var(--muted)}.err{color:var(--bad);font-weight:700}a{color:var(--teal)}
@media(max-width:600px){main{margin:12px auto}.card{padding:14px}}
`;

function layout(title: string, body: string, script = ''): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<link href="https://fonts.googleapis.com/css2?family=Marcellus&family=Mulish:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>${CSS}</style></head>
<body><header>${esc(config.label)} <small>· demo BU app · ${esc(config.clientId)} · ${esc(config.baseUrl)}</small></header>
<main>${body}</main>${script}</body></html>`;
}

/** The app card (same layout as the Test Console "Applications (Business Units)" cards). */
export function homePage(b: BrowserState, backchannelDown: boolean, hasSecret: boolean): string {
  const s = b.session;
  const c = s?.claims ?? {};
  const problem =
    (hasSecret ? '' : '<div class="status err">No client secret: set CLIENT_SECRET or CLIENT_SECRET_FILE in .env</div>') +
    (b.lastError ? `<div class="status err">${esc(b.lastError)}</div>` : '');
  const state = s
    ? `<div class="status in"><b>${esc(c.name ?? 'ITS ' + String(c.sub))}</b> · ITS ${esc(c.sub)}
        <div class="kv"><b>acr</b><span class="mono">${esc(c.acr)}</span><b>amr</b><span class="mono">${esc(Array.isArray(c.amr) ? c.amr.join(', ') : c.amr)}</span>
        <b>sid</b><span class="mono">${esc(c.sid)}</span><b>aud</b><span class="mono">${esc(c.aud)}</span>
        <b>auth_time</b><span>${typeof c.auth_time === 'number' ? esc(new Date(c.auth_time * 1000).toLocaleTimeString()) : ''}</span><b>signed by</b><span class="mono">${esc(s.kid)}</span>
        ${c.source_client_id ? `<b>via</b><span>trusted handoff from <code>${esc(c.source_client_id)}</code></span>` : ''}</div></div>
       <details><summary>ID token claims · /me</summary><pre>${esc(JSON.stringify(c, null, 2))}</pre><pre>${esc(JSON.stringify(s.me, null, 2))}</pre></details>`
    : '<div class="status out">Not signed in to this app</div>';
  const peers = config.peers.map((p) => `<option value="${esc(p.clientId)}">${esc(p.label)} (${esc(p.realm)})</option>`).join('');
  const paths = HANDOFF_PATH_OPTIONS.map((p) => `<option>${esc(p)}</option>`).join('');
  const events = b.events.length
    ? `<ul class="events">${b.events.map((e) => `<li class="${e.ok ? '' : 'no'}"><span class="muted">${esc(time(e.at))}</span> ${esc(e.text)}</li>`).join('')}</ul>`
    : '';

  const body = `<h2>Application (Business Unit)</h2>
<div class="card">
  <h3>${esc(config.label)}<span class="realm ${esc(config.realm)}">${esc(config.realm)}</span></h3>
  <div class="meta mono">${esc(config.clientId)} · ${esc(config.baseUrl)} · Core ${esc(config.issuer)}</div>
  <div class="btns">
    <a class="btn" href="/login">Sign in (AAL1)</a>
    <a class="btn gold" href="/login?acr=aal2">Sign in + MFA (AAL2)</a>
    <a class="btn light" href="/login?acr=aal2&amp;max_age=60">AAL2 · MFA ≤ 60 s</a>
  </div>
  <div class="btns">
    <a class="btn red" href="/logout">Logout (all ${esc(config.realm)} apps)</a>
    ${s || b.lastError || b.events.length ? '<a class="btn light" href="/clear">Clear</a>' : ''}
  </div>
  ${problem}${state}
  <form class="handoff" method="get" action="/handoff">
    <span>Open another app via handoff:</span>
    <select name="target">${peers}</select>
    <select name="path">${paths}</select>
    <button class="btn light" type="submit">Open via handoff</button>
  </form>
  <div class="bc"><label><input type="checkbox" id="bcdown" ${backchannelDown ? 'checked' : ''}> back-channel endpoint down (503)</label></div>
  ${events}
</div>`;

  // Refresh when something changes server side (e.g. a back-channel logout from Core).
  const script = `<script>
const V=${b.version};
document.getElementById('bcdown').addEventListener('change',async e=>{await fetch('/api/backchannel',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:'down='+(e.target.checked?1:0)});location.reload();});
setInterval(async()=>{try{const r=await fetch('/api/version');const j=await r.json();if(j.version!==V)location.reload();}catch{}},2000);
</script>`;
  return layout(config.label, body, script);
}

/** Landing pages a handoff opens (/dashboard, /events/..., /bookings/..., /admin/...). */
export function landingPage(b: BrowserState, pathWithQuery: string): string {
  const c = b.session!.claims;
  return layout(
    `${config.label} · ${pathWithQuery}`,
    `<div class="card"><h2>${esc(pathWithQuery)}</h2>
     <p>Signed in to <b>${esc(config.label)}</b> as <b>${esc(c.name ?? 'ITS ' + String(c.sub))}</b> (ITS ${esc(c.sub)}), realm ${esc(c.auth_realm)}, ${esc(c.acr)}.</p>
     ${c.source_client_id ? `<p>Arrived by <b>trusted handoff</b> from <code>${esc(c.source_client_id)}</code> - no second login, no token exchange. Core session sid <code>${esc(String(c.sid).slice(0, 8))}</code>.</p>` : ''}
     <p><a href="/">Back to ${esc(config.label)}</a></p></div>`,
  );
}

export function messagePage(title: string, html: string): string {
  return layout(`${config.label} · ${title}`, `<div class="card"><h2>${esc(title)}</h2>${html}<p><a href="/">Back to ${esc(config.label)}</a></p></div>`);
}
