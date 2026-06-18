import express from "express";
import fs from "node:fs";
import { execFile } from "node:child_process";

const app = express();

app.post("/webhook", express.json(), (req, res) => {
  const token = process.env.API_TOKEN;
  const payload = JSON.stringify(req.body);
  fs.writeFileSync(`/tmp/${req.body.name}.json`, payload);
  execFile("notify-send", [token, payload]);
  res.json({ ok: true });
});

app.listen(3000);
