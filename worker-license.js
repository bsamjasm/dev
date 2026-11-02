// Cloudflare Worker: licenses — ترخيص عن بعد للعملاء
// Binding: LICENSES (KV namespace) | Secrets: DEV_USER (اسم المطور) + DEV_PASS (كلمة سر المطور)
const H = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization, Content-Type", "Access-Control-Allow-Methods": "GET, POST, OPTIONS" };
const R = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...H, "Content-Type": "application/json" } });
const KEY = /^[A-Za-z0-9_-]{6,64}$/;

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: H });
    const u = new URL(req.url);

    // فحص الترخيص (يستدعيه المتجر واللوحة)
    if (u.pathname === "/check") {
      const k = u.searchParams.get("k") || "";
      if (!KEY.test(k)) return R({ ok: false, reason: "invalid" });
      const v = await env.LICENSES.get("c:" + k, "json");
      if (!v) return R({ ok: false, reason: "invalid" });
      if (!v.active) return R({ ok: false, reason: "suspended" });
      if (Date.now() > v.exp) return R({ ok: false, reason: "expired" });
      return R({ ok: true, exp: v.exp });
    }

    // إدارة العملاء (للمطور فقط)
    if (u.pathname === "/admin" && req.method === "POST") {
      const pass = (req.headers.get("Authorization") || "").replace("Bearer ", "");
      if (!env.DEV_PASS || !env.DEV_USER || pass !== env.DEV_USER + ":" + env.DEV_PASS) return R({ error: "denied" }, 401);
      let b; try { b = await req.json(); } catch (e) { return R({ error: "bad" }, 400); }

      if (b.op === "list") {
        const l = await env.LICENSES.list({ prefix: "c:" });
        const items = [];
        for (const x of l.keys) items.push({ key: x.name.slice(2), ...(await env.LICENSES.get(x.name, "json")) });
        return R({ items });
      }
      if (b.op === "set") {
        if (!KEY.test(b.key || "")) return R({ error: "key" }, 400);
        const old = (await env.LICENSES.get("c:" + b.key, "json")) || {};
        const exp = b.days ? Math.max(Date.now(), old.exp || 0) + Number(b.days) * 864e5 : (b.exp ?? old.exp ?? 0);
        const v = { name: b.name ?? old.name ?? "", active: b.active ?? old.active ?? true, exp };
        await env.LICENSES.put("c:" + b.key, JSON.stringify(v));
        return R({ ok: true, ...v });
      }
      if (b.op === "del") { await env.LICENSES.delete("c:" + b.key); return R({ ok: true }); }
    }
    return R({ error: "not found" }, 404);
  }
};
