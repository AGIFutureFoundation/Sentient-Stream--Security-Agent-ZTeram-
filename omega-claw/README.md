# Omega-Claw

A minimal multi-agent orchestration framework for hacking fast. Used to build Sentinel Stream at the Cyberdefense Hackathon.

**Omega** = the orchestrator. Decomposes the build plan into tasks, dispatches to claws, reviews outputs, triggers re-runs.

**Claws** = worker agents. Each claw has one specialty, one metaprompt, one console log, and ships concrete artifacts.

```
        ┌─────────────────────────────────────────────┐
        │  OMEGA (orchestrator)                        │
        │  • reads ROADMAP.md                          │
        │  • decomposes into task graph                 │
        │  • dispatches to claws                        │
        │  • reviews artifacts against success criteria│
        └────────────┬────────────────────────────────┘
                     │
       ┌─────────────┼─────────────┬─────────────┐
       ▼             ▼             ▼             ▼
   claw-data   claw-detection  claw-ui   claw-evals
       │             │             │             │
       ▼             ▼             ▼             ▼
   schema.sql   detect.py      dashboard/   evals/
   ingest.py    alert.py       nl_query.py  runner.py
```

## Files

- [`orchestrator.py`](./orchestrator.py) — Omega's runtime. Reads `ROADMAP.md`, decomposes into a task DAG, dispatches to claws, polls for completion, reviews outputs.
- [`claw_agent.py`](./claw_agent.py) — Generic claw worker. Takes a metaprompt + task spec, executes via LLM call, writes artifacts + console log.
- [`agents.yaml`](./agents.yaml) — Claw definitions: name, specialty, metaprompt file, owned paths.
- [`run.py`](./run.py) — CLI entry point. `python -m omega_claw.run --plan ROADMAP.md`.
- [`metaprompts/`](./metaprompts/) — Prompt templates that **generate** prompts (meta-prompting). Each template is itself a prompt that Omega uses to produce the final task-specific prompt for a claw.
- [`consoles/`](./consoles/) — Append-only console log per agent. Every action an agent takes is recorded with timestamp, prompt used, LLM response, and artifact path. These are the **audit trail** of the build — useful for the demo video.

## How it works

1. Omega reads `ROADMAP.md`, identifies success criteria + timeline.
2. Omega invokes the `task-decomposer` metaprompt to produce a DAG of tasks, each tagged with the responsible claw.
3. For each task, Omega:
   - Loads the claw's metaprompt template from `metaprompts/<role>.md`
   - Fills it with the task spec
   - Calls the LLM
   - Writes the LLM's output to the artifact path
   - Appends a console entry to `consoles/<role>.md`
4. Omega reviews artifacts against success criteria. If a claw fails (e.g. eval recall <0.85), Omega dispatches a re-run with refined prompt.
5. Omega writes its own console log to `consoles/omega.md` for traceability.

## Why "Omega-Claw"?

- **Omega** = the last letter, the orchestrator that closes the loop.
- **Claw** = grabs a task and won't let go until it ships.

It's a hackathon codename. Don't read too much into it.

## Usage

```bash
# Install deps
pip install -r requirements.txt

# Run the full build (Omega decomposes + dispatches all claws)
make omega

# Run just the evals track
make omega-evals

# Or directly
python -m omega_claw.run --plan ROADMAP.md
python -m omega_claw.run --plan ROADMAP.md --track evals
```

## Reproducibility

Every Omega run is captured in `consoles/`. To reproduce a build:

1. Read `consoles/omega.md` to see the task decomposition
2. For each task, read the corresponding `consoles/claw-<role>.md` entry
3. Re-run the metaprompt with the same task spec → same artifact

The console logs in this repo are from the **actual build** of Sentinel Stream at the hackathon.
