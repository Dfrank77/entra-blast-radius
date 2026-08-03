"""HTML reports for blast radius: single-identity and tenant-wide.

Matched to the Entra security suite palette. Single-identity renders a
verdict hero plus the full reachable set. Tenant-wide renders a ranked,
collapsible list - each identity collapsed to its verdict, click to
expand the full detail.
"""

from html import escape
from datetime import datetime, timezone


_CSS = """
:root {
  --bg: #ffffff; --card: #fff; --border: #e5e7eb;
  --text: #0f172a; --muted: #64748b;
  --crit: #ff0000; --crit-bg: #ffb3b3;
  --high: #ff7a00; --high-bg: #ffcc99;
  --ok: #16a34a; --ok-bg: #bbf7d0;
  --step-bg: #ffffff; --step-border: #d9dee5;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.45; }
main { max-width: 900px; margin: 0 auto; padding: 2.5rem 1.5rem; }
h1 { font-size: 1.8rem; margin: 0 0 .2rem; }
.subtitle { color: var(--muted); margin: 0 0 .1rem; }
.ts { color: var(--muted); font-size: .85rem; margin: 0 0 1.5rem; }
h2.section { font-size: 1.1rem; margin: 2rem 0 .9rem; padding-bottom: .35rem; border-bottom: 1px solid var(--border); }
.verdict { border-radius: 14px; padding: 1.4rem 1.6rem; margin-bottom: 1.75rem; border: 1px solid var(--border); border-left: 8px solid var(--crit); }
.verdict.crit { background: var(--crit-bg); border-left-color: var(--crit); }
.verdict.high { background: var(--high-bg); border-left-color: var(--high); }
.verdict.ok { background: var(--ok-bg); border-left-color: var(--ok); }
.verdict .label { font-size: .72rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: #7f1d1d; }
.verdict.high .label { color: #7c2d12; }
.verdict.ok .label { color: #14532d; }
.verdict .headline { font-size: 1.35rem; font-weight: 800; margin: .3rem 0 0; }
.verdict .sub { color: #334155; font-size: .95rem; margin-top: .4rem; }
.reach { display: flex; gap: 2rem; flex-wrap: wrap; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.4rem; margin-bottom: 1rem; }
.reach .n { font-size: 1.6rem; font-weight: 700; display: block; line-height: 1; }
.reach .l { font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.card { background: var(--card); border: 1px solid var(--border); border-left: 6px solid var(--border); border-radius: 12px; padding: .9rem 1.2rem; margin-bottom: .8rem; }
.card.t0 { background: var(--crit-bg); border-left-color: var(--crit); }
.card.t1 { background: var(--high-bg); border-left-color: var(--high); }
.card-head { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
.badge { color: #fff; font-size: .68rem; font-weight: 700; letter-spacing: .05em; padding: .16rem .5rem; border-radius: 999px; text-transform: uppercase; }
.badge.t0 { background: var(--crit); }
.badge.t1 { background: var(--high); }
.badge.t2 { background: var(--muted); }
.name { font-size: 1.05rem; font-weight: 700; }
.perm-tag { font-family: ui-monospace, Menlo, monospace; font-size: .76rem; background: rgba(0,0,0,0.07); padding: .12rem .45rem; border-radius: 5px; }
.via { margin-left: auto; font-size: .78rem; color: #475569; background: rgba(255,255,255,0.7); border: 1px solid var(--step-border); padding: .14rem .5rem; border-radius: 999px; white-space: nowrap; }
.kind { font-size: .78rem; color: #475569; }
.groups { display: flex; flex-wrap: wrap; gap: .4rem; }
.group-chip { background: var(--step-bg); border: 1px solid var(--step-border); border-radius: 6px; padding: .28rem .55rem; font-size: .82rem; }
.empty { color: var(--muted); padding: 1rem; }
.rank-card { background: var(--card); border: 1px solid var(--border); border-left: 6px solid var(--border); border-radius: 12px; margin-bottom: .7rem; overflow: hidden; }
.rank-card.crit { border-left-color: var(--crit); }
.rank-card.high { border-left-color: var(--high); }
.rank-card.ok { border-left-color: var(--ok); }
.rank-head { display: flex; align-items: center; gap: .8rem; padding: .9rem 1.2rem; cursor: pointer; user-select: none; }
.rank-head:hover { background: rgba(0,0,0,0.02); }
.rank-num { font-size: 1.1rem; font-weight: 800; color: var(--muted); min-width: 1.8rem; }
.rank-name { font-size: 1.05rem; font-weight: 700; }
.rank-verdict { color: #334155; font-size: .9rem; }
.rank-card.crit .rank-verdict { color: #7f1d1d; font-weight: 600; }
.chev { margin-left: auto; color: var(--muted); transition: transform .15s; }
.rank-card.open .chev { transform: rotate(90deg); }
.rank-detail { display: none; padding: .3rem 1.2rem 1.2rem; border-top: 1px solid var(--border); }
.rank-card.open .rank-detail { display: block; }
.dsection { font-size: .95rem; margin: 1.1rem 0 .6rem; color: var(--muted); }
"""

_TIER_BADGE = {"TIER0": ("t0", "T0"), "TIER1": ("t1", "T1"), "TIER2": ("t2", "T2")}


def _verdict_bits(result):
    roles = result["roles"]
    apps = result["apps"]
    overall = result.get("overall_tier", 9)
    via_app = result.get("worst_via_app", False)
    tier0_apps = [a for a in apps if a["worst"] == "TIER0"]
    if overall == 0:
        vclass, vlabel = "crit", "Critical - full tenant control reachable"
        if via_app and tier0_apps:
            a = tier0_apps[0]
            perm = a["tier0_perms"][0] if a["tier0_perms"] else "tier-0 permission"
            headline = "Reaches FULL TENANT CONTROL via owned app '" + escape(a["app"]) + "'"
            sub = ("Holds " + escape(perm) + " through an application this identity owns. "
                   "The owner holds no tier-0 role directly - the reach is through the app.")
        else:
            w = roles[0]
            headline = "Reaches FULL TENANT CONTROL: " + escape(w["role"])
            sub = ("Held" if w["kind"] == "active" else "PIM-eligible") + " via " + escape(w["via"]) + "."
    elif overall == 1:
        vclass, vlabel = "high", "High - broad privileged reach"
        w = roles[0] if roles else None
        headline = ("Worst reachable: " + escape(w["role"])) if w else "Reaches tier-1 privilege"
        sub = (("Held" if w["kind"] == "active" else "PIM-eligible") + " via " + escape(w["via"]) + ".") if w else ""
    else:
        vclass, vlabel = "ok", "Limited reach"
        headline = "No tier-0 or tier-1 privilege reachable"
        sub = "This identity's reachable set contains no highly privileged roles or app permissions."
    return vclass, vlabel, headline, sub


def _role_cards(roles):
    if not roles:
        return '<div class="empty">No directory roles reachable.</div>'
    out = ""
    for r in roles:
        bcls, btxt = _TIER_BADGE[r["tier"]]
        cardcls = bcls if r["tier"] != "TIER2" else ""
        kind = "held" if r["kind"] == "active" else "PIM-eligible"
        out += ('<div class="card ' + cardcls + '"><div class="card-head">'
                '<span class="badge ' + bcls + '">' + btxt + '</span>'
                '<span class="name">' + escape(r["role"]) + '</span>'
                '<span class="kind">' + kind + '</span>'
                '<span class="via">via ' + escape(r["via"]) + '</span>'
                '</div></div>')
    return out


def _app_cards(apps):
    if not apps:
        return '<div class="empty">No owned applications.</div>'
    out = ""
    order = {"TIER0": 0, "TIER1": 1, "TIER2": 2}
    for a in sorted(apps, key=lambda x: order.get(x["worst"], 9)):
        cls = "t0" if a["tier0_perms"] else ("t1" if a["tier1_perms"] else "")
        bcls, btxt = _TIER_BADGE[a["worst"]]
        perms = a["tier0_perms"] + a["tier1_perms"]
        perm_tags = "".join('<span class="perm-tag">' + escape(x) + "</span> " for x in perms)
        out += ('<div class="card ' + cls + '"><div class="card-head">'
                '<span class="badge ' + bcls + '">' + btxt + '</span>'
                '<span class="name">' + escape(a["app"]) + '</span></div>'
                + (('<div style="margin-top:.4rem">' + perm_tags + '</div>') if perms else "")
                + '</div>')
    return out


def _group_chips(groups):
    if not groups:
        return '<span class="empty">None</span>'
    return "".join('<span class="group-chip">' + escape(g[1]) + "</span>" for g in groups)


def _detail_body(result):
    return ('<h3 class="dsection">Reachable roles (worst first)</h3>'
            + _role_cards(result["roles"])
            + '<h3 class="dsection">Owned applications</h3>'
            + _app_cards(result["apps"])
            + '<h3 class="dsection">Group memberships</h3>'
            + '<div class="groups">' + _group_chips(result["groups"]) + '</div>')


def render_html(result, output_path="blast_radius_report.html"):
    if not result:
        return None
    p = result["principal"]
    roles, apps, groups = result["roles"], result["apps"], result["groups"]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    vclass, vlabel, headline, sub = _verdict_bits(result)

    html = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Blast Radius - " + escape(p["name"]) + "</title>"
            "<style>" + _CSS + "</style></head><body><main>"
            "<h1>Blast Radius</h1>"
            "<p class=\"subtitle\">" + escape(p["name"]) + "</p>"
            "<p class=\"ts\">" + ts + "</p>"
            "<div class=\"verdict " + vclass + "\">"
            "<div class=\"label\">" + escape(vlabel) + "</div>"
            "<div class=\"headline\">" + headline + "</div>"
            + (('<div class="sub">' + sub + "</div>") if sub else "")
            + "</div>"
            "<div class=\"reach\">"
            "<div><span class=\"n\">" + str(len(roles)) + "</span><span class=\"l\">reachable roles</span></div>"
            "<div><span class=\"n\">" + str(len(apps)) + "</span><span class=\"l\">owned apps</span></div>"
            "<div><span class=\"n\">" + str(len(groups)) + "</span><span class=\"l\">groups (nested incl.)</span></div>"
            "</div>"
            + _detail_body(result)
            + "</main></body></html>")

    with open(output_path, "w") as f:
        f.write(html)
    return output_path


def render_tenant(results, total, output_path="blast_radius_tenant.html"):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    crit_count = sum(1 for r in results if r.get("overall_tier", 9) == 0)

    cards = ""
    for i, r in enumerate(results, 1):
        vclass, vlabel, headline, sub = _verdict_bits(r)
        p = r["principal"]
        cards += ('<div class="rank-card ' + vclass + '" onclick="this.classList.toggle(\'open\')">'
                  '<div class="rank-head">'
                  '<span class="rank-num">' + str(i) + '</span>'
                  '<span class="rank-name">' + escape(p["name"]) + '</span>'
                  '<span class="rank-verdict">' + headline + '</span>'
                  '<span class="chev">&#9656;</span>'
                  '</div>'
                  '<div class="rank-detail">' + _detail_body(r) + '</div>'
                  '</div>')

    html = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Tenant Blast Radius</title>"
            "<style>" + _CSS + "</style></head><body><main>"
            "<h1>Tenant Blast Radius</h1>"
            "<p class=\"subtitle\">Top " + str(len(results)) + " most dangerous identities of " + str(total) + " users</p>"
            "<p class=\"ts\">" + ts + "</p>"
            "<div class=\"reach\">"
            "<div><span class=\"n\" style=\"color:var(--crit)\">" + str(crit_count) + "</span><span class=\"l\">reach full tenant control</span></div>"
            "<div><span class=\"n\">" + str(len(results)) + "</span><span class=\"l\">shown</span></div>"
            "<div><span class=\"n\">" + str(total) + "</span><span class=\"l\">total users</span></div>"
            "</div>"
            "<p style=\"color:var(--muted);font-size:.85rem;margin:.5rem 0 1.5rem\">Click any identity to expand its full reachable set.</p>"
            + cards
            + "</main></body></html>")

    with open(output_path, "w") as f:
        f.write(html)
    return output_path
