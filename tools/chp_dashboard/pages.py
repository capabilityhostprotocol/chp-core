"""HTML page templates — f-string functions, inline CSS, no build step."""

from __future__ import annotations

import html
import json

_CSS = """
  :root { --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e2e8f0;
          --dim:#64748b; --green:#4ade80; --red:#f87171; --yellow:#fbbf24;
          --blue:#60a5fa; --accent:#818cf8; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:
    ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; padding:24px; }
  h1 { font-size:18px; color:var(--accent); margin-bottom:16px; }
  h2 { font-size:14px; color:var(--dim); margin:20px 0 8px; text-transform:uppercase;
       letter-spacing:.05em; }
  a { color:var(--blue); text-decoration:none; }
  a:hover { text-decoration:underline; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:8px;
          padding:16px; margin-bottom:16px; }
  table { width:100%; border-collapse:collapse; }
  th { color:var(--dim); text-align:left; padding:6px 12px; font-size:11px;
       text-transform:uppercase; letter-spacing:.05em; border-bottom:1px solid var(--border); }
  td { padding:8px 12px; border-bottom:1px solid var(--border); }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:rgba(255,255,255,.03); }
  .ok   { color:var(--green); }
  .fail { color:var(--red); }
  .warn { color:var(--yellow); }
  .dim  { color:var(--dim); }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px;
           font-weight:600; }
  .badge-ok   { background:rgba(74,222,128,.15); color:var(--green); }
  .badge-fail { background:rgba(248,113,113,.15); color:var(--red); }
  .badge-warn { background:rgba(251,191,36,.15); color:var(--yellow); }
  .nav { display:flex; gap:16px; margin-bottom:24px; padding-bottom:16px;
         border-bottom:1px solid var(--border); align-items:center; }
  .nav a { color:var(--dim); }
  .nav a:hover { color:var(--text); }
  pre { background:var(--card); border:1px solid var(--border); border-radius:6px;
        padding:12px; overflow-x:auto; line-height:1.6; }
  .stat { display:inline-block; margin-right:24px; }
  .stat-val { font-size:20px; font-weight:700; color:var(--text); }
  .stat-lbl { font-size:11px; color:var(--dim); text-transform:uppercase; }
"""

_NAV = '<nav class="nav"><strong style="color:var(--accent)">CHP</strong>' \
       '<a href="/">Sessions</a><a href="/breakdown">Breakdown</a></nav>'


def _wrap(title: str, body: str) -> str:
    return (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{html.escape(title)} — CHP Dashboard</title>'
        f'<style>{_CSS}</style></head><body>{_NAV}{body}</body></html>'
    )


def sessions_page(events: list[dict]) -> str:
    if not events:
        body = '<div class="card"><p class="dim">No sessions recorded yet. ' \
               'Run <code>chp hooks install</code> to start capturing evidence.</p></div>'
        return _wrap("Sessions", f"<h1>Sessions</h1>{body}")

    rows = ""
    for ev in events:
        sid = html.escape((ev.get("correlation") or {}).get("correlation_id", "?"))
        ts = html.escape((ev.get("timestamp") or "")[:19].replace("T", " "))
        tools = (ev.get("payload") or {}).get("tool_count", "?")
        rows += (
            f'<tr><td><a href="/session/{sid}">{sid}</a></td>'
            f'<td style="text-align:right">{tools}</td>'
            f'<td class="dim">{ts}</td></tr>\n'
        )

    table = (
        '<table><thead><tr><th>Session ID</th><th style="text-align:right">Tools</th>'
        '<th>Timestamp</th></tr></thead><tbody>' + rows + '</tbody></table>'
    )
    body = f'<h1>Sessions <span class="dim" style="font-size:13px">({len(events)} recent)</span></h1>' \
           f'<div class="card">{table}</div>'
    return _wrap("Sessions", body)


def session_detail_page(session_id: str, events: list[dict], chain_valid: bool, children: list[str]) -> str:
    tool_evs  = [e for e in events if e["event_type"] == "tool_use"]
    failures  = [e for e in events if e.get("outcome") == "failure"]
    denials   = [e for e in events if e.get("outcome") == "denied"]

    ts_list = [e["timestamp"] for e in events if e.get("timestamp")]
    dur_str = "—"
    if len(ts_list) >= 2:
        from datetime import datetime
        def _p(t): return datetime.fromisoformat(t.replace("Z", "+00:00"))
        dur_str = f"{(_p(ts_list[-1]) - _p(ts_list[0])).total_seconds():.1f}s"

    chain_badge = (
        '<span class="badge badge-ok">chain ok</span>' if chain_valid
        else '<span class="badge badge-fail">chain broken</span>'
    )
    fail_badge  = (
        f'<span class="badge badge-fail">{len(failures)} failure(s)</span> ' if failures else ""
    )
    deny_badge  = (
        f'<span class="badge badge-warn">{len(denials)} denied</span>' if denials else ""
    )

    stats = (
        f'<div class="card" style="margin-bottom:12px">'
        f'<div class="stat"><div class="stat-val">{len(tool_evs)}</div>'
        f'<div class="stat-lbl">Tool calls</div></div>'
        f'<div class="stat"><div class="stat-val">{dur_str}</div>'
        f'<div class="stat-lbl">Duration</div></div>'
        f'<div class="stat"><div class="stat-val">{len(events)}</div>'
        f'<div class="stat-lbl">Events</div></div>'
        f'&nbsp;&nbsp;{chain_badge}&nbsp;{fail_badge}{deny_badge}'
        f'</div>'
    )

    # Tool call table
    rows = ""
    for ev in tool_evs:
        p = ev.get("payload") or {}
        tn = html.escape(p.get("tool_name") or ev.get("capability_id") or "")
        inp = p.get("tool_input") or {}
        preview = ""
        for key in ("command", "file_path", "url", "query", "pattern"):
            val = inp.get(key)
            if val:
                preview = f"{key}={str(val)[:60]!r}"
                break
        out = ev.get("outcome") or ""
        cls = "ok" if out == "success" else "fail" if out == "failure" else "warn"
        seq = ev.get("sequence", "")
        rows += (
            f'<tr><td class="dim">{seq}</td><td>{html.escape(tn)}</td>'
            f'<td class="dim">{html.escape(preview)}</td>'
            f'<td class="{cls}">{html.escape(out)}</td></tr>\n'
        )

    tool_table = (
        '<div class="card"><h2>Tool calls</h2>'
        '<table><thead><tr><th>Seq</th><th>Tool</th><th>Input</th><th>Outcome</th></tr></thead>'
        '<tbody>' + (rows or '<tr><td colspan="4" class="dim">No tool calls</td></tr>') +
        '</tbody></table></div>'
    )

    children_html = ""
    if children:
        child_links = " &nbsp;·&nbsp; ".join(
            f'<a href="/session/{html.escape(c)}">{html.escape(c)}</a>' for c in children
        )
        children_html = f'<div class="card"><h2>Spawned sessions</h2><p>{child_links}</p></div>'

    sid = html.escape(session_id)
    body = (
        f'<h1>Session: <span style="color:var(--text)">{sid}</span></h1>'
        f'{stats}{tool_table}{children_html}'
        f'<p style="margin-top:16px"><a href="/session/{sid}/tree">View session tree →</a></p>'
    )
    return _wrap(f"Session {session_id}", body)


def tree_page(session_id: str, tree_text: str) -> str:
    body = (
        f'<h1>Session tree: <span style="color:var(--text)">{html.escape(session_id)}</span></h1>'
        f'<pre>{html.escape(tree_text)}</pre>'
        f'<p style="margin-top:16px"><a href="/session/{html.escape(session_id)}">← Back to session</a></p>'
    )
    return _wrap(f"Tree {session_id}", body)


def breakdown_page(counts: dict[str, dict[str, int]]) -> str:
    if not counts:
        body = '<div class="card"><p class="dim">No evidence data.</p></div>'
        return _wrap("Breakdown", f"<h1>Capability Breakdown</h1>{body}")

    cols = ["success", "failure", "denied"]
    hdr = "<tr><th>Capability</th>" + "".join(f"<th>{c}</th>" for c in cols) + "<th>other</th></tr>"
    rows = ""
    for cap in sorted(counts):
        oc = counts[cap]
        cells = ""
        for c in cols:
            v = oc.get(c, 0)
            cls = " class=\"ok\"" if c == "success" and v else (" class=\"fail\"" if c == "failure" and v else (" class=\"warn\"" if c == "denied" and v else ""))
            cells += f"<td{cls}>{v if v else ''}</td>"
        other = sum(v for k, v in oc.items() if k not in cols)
        cells += f"<td class=\"dim\">{other if other else ''}</td>"
        rows += f"<tr><td>{html.escape(cap)}</td>{cells}</tr>\n"

    body = (
        f'<h1>Capability Breakdown</h1>'
        f'<div class="card"><table><thead>{hdr}</thead><tbody>{rows}</tbody></table></div>'
    )
    return _wrap("Breakdown", body)


def error_page(status: int, message: str) -> str:
    body = f'<div class="card"><p class="fail">{status}: {html.escape(message)}</p></div>'
    return _wrap("Error", body)
