# Sentinel Stream — 2-Minute Demo Video Script

**Total runtime:** 2:00 (120 seconds)
**Format:** Single-take screen recording with voiceover.
**Player:** `demo-video/index.html` (synced HTML artifact — playable in any browser)

---

## 0:00–0:10 — Cold open (10s)

**Visual:** Dashboard loads. Black screen, then Sentinel Stream logo fades in. Live ticker starts scrolling.

**Voiceover:**
> "Every team shipping LLM agents has the same blind spot: no one is watching the agent event stream. Sentinel Stream is the SOC for AI."

---

## 0:10–0:25 — The threat (15s)

**Visual:** Three MITRE ATLAS technique badges animate in:
- `AML.T0051` — Prompt Injection
- `AML.T0063` — Tool Abuse
- `AML.T0057` — Context Exfiltration

**Voiceover:**
> "Prompt injection. Tool abuse. Context exfiltration. MITRE ATLAS catalogues dozens of these techniques — and your SIEM doesn't see any of them."

---

## 0:25–0:45 — The architecture (20s)

**Visual:** Architecture diagram animates in left-to-right. Synthetic generator → FastAPI → ClickHouse → Detection engine → Dashboard.

**Voiceover:**
> "Sentinel Stream ingests every LLM event — prompts, tool calls, retrievals, model responses — into ClickHouse. Three detection rule families run in real time. Alerts surface with MITRE ATLAS labels in under two seconds."

---

## 0:45–1:30 — Live demo: prompt injection (45s)

**Visual:** Cut to live dashboard. Live event ticker scrolling at 200 events/sec. Cursor moves to "Inject Attack" button. Click.

**Voiceover:**
> "Watch. We inject a prompt-injection attack. Within 1.4 seconds…"

**Visual:** Alert card slides in from the right. Severity = HIGH. Technique badge = AML.T0051. Click the card → forensic timeline expands below showing the triggering event with full payload.

**Voiceover:**
> "An alert fires — high severity, tagged AML.T0051. Click it, and we get the full forensic event chain: the triggering prompt, the agent it hit, every related event."

---

## 1:30–1:50 — NL query + ClickHouse latency (20s)

**Visual:** Cursor moves to NL query box. Types: "show all agents that called filesystem after 'ignore previous'". Hits Run.

**Voiceover:**
> "Now investigate. Natural-language query, template-constrained, sandboxed. We ask: which agents called the filesystem tool after receiving a prompt containing 'ignore previous'?"

**Visual:** Results table appears. Footer updates: "142ms · 2.3M rows scanned · CH p99: 84ms".

**Voiceover:**
> "142 milliseconds across 2.3 million rows. ClickHouse p99 query latency: 84 milliseconds."

---

## 1:50–2:00 — Close (10s)

**Visual:** Cut to title card. "Sentinel Stream — the SOC for AI." Team name + repo URL.

**Voiceover:**
> "Sentinel Stream. Built on ClickHouse. Built with the Omega-Claw multi-agent framework. Show me the attack, not the dashboard."

---

## Production notes

- **Tool:** OBS Studio or Loom. 1920×1080, 30fps, MP4.
- **Audio:** USB mic, no music bed (keeps voice clear).
- **Pacing:** Speak at ~150 words/min. Total script ≈ 300 words → 2:00.
- **Cuts:** Keep cuts minimal — judges want to see real-time, not edited highlights.
- **Hosted at:** `demo-video/index.html` (HTML artifact that plays the script with synced visuals — usable even before the video is recorded).

## HTML artifact

The `demo-video/index.html` file in this repo is a standalone HTML "video player" that:
1. Plays through the 5 segments above with synced visuals
2. Has a play/pause button + progress bar
3. Auto-advances segments at the timestamps in this script
4. Shows the voiceover text below the visual for accessibility

Open it in any browser to preview the demo flow before recording the actual video.
