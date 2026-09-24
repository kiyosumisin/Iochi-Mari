// Mari's Gemini relay. Google blocks the Gemini API from the bot's Hong Kong
// VPS, so the bot sends its calls here (a Vercel function in a US region) and
// they are forwarded unchanged. The Gemini key travels with each request; only
// the relay token lives on Vercel, so strangers cannot use this relay.
const UPSTREAM = "https://generativelanguage.googleapis.com";

module.exports = async (req, res) => {
  const token = process.env.RELAY_TOKEN;
  if (!token || req.headers["x-relay-token"] !== token) {
    return res.status(403).json({ error: "forbidden" });
  }

  const { path = "", ...query } = req.query; // path comes from the rewrite in vercel.json
  if (!/^v1(beta)?\//.test(path)) {
    return res.status(404).json({ error: "not found" });
  }
  const qs = new URLSearchParams(query).toString();

  const upstream = await fetch(`${UPSTREAM}/${path}${qs ? `?${qs}` : ""}`, {
    method: req.method,
    headers: {
      "content-type": "application/json",
      "x-goog-api-key": req.headers["x-goog-api-key"] || "",
    },
    body: req.method === "GET" ? undefined : JSON.stringify(req.body ?? {}),
  });

  res.status(upstream.status);
  res.setHeader("content-type", upstream.headers.get("content-type") || "application/json");
  res.send(Buffer.from(await upstream.arrayBuffer()));
};
