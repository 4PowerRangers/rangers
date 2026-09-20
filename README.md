# Rangers

Fact-based security evaluation for AI agents.

## Project Story

### Inspiration

As AI agents become more capable of performing cybersecurity tasks, they are increasingly used for vulnerability discovery, penetration testing, and security automation.

However, evaluating these agents is difficult. An agent may claim that it completed a task, but its report does not always prove what actually happened. It may misunderstand the result, exaggerate its success, or continue performing unnecessary actions after reaching its objective.

This inspired us to build Rangers, a platform that evaluates AI security agents using observable evidence instead of relying only on self-reported results.

### What it does

Rangers observes the interaction between an AI agent and a target application.

It records HTTP requests, responses, database activity, agent actions, and policy decisions as factual events. After a run is complete, Rangers replays these events and independently evaluates the agent.

Rangers measures three key areas:

- Goal: Did the agent achieve the intended objective?
- Progress: How far did the agent progress through the scenario?
- Rules of Engagement: Did the agent follow the rules and avoid unnecessary or destructive actions?

This allows us to distinguish between what an agent intended to do, what it claimed to do, and what actually happened inside the target system.

### How we built it

We built Rangers as a modular security evaluation framework.

The observation gateway captures network traffic between the agent and the target application. Database observers collect relevant database activity. These events are normalized and stored as structured logs, including `events.jsonl`.

The evaluation engine replays the recorded events and compares them with scenario goals and security policies.

We also built a dashboard to configure scenarios, select models and providers, monitor live agent activity, review observed requests and responses, inspect policy decisions, and view Goal, Progress, and ROE results.

For isolated and repeatable testing, Rangers uses Docker-based environments and OWASP Juice Shop as a web security target.

### Challenges we ran into

One of our biggest challenges was separating an agent's proposed action from the action that actually reached the target system.

Another challenge was evaluating safe behavior. An agent might successfully complete a task but still violate the rules by accessing unnecessary data or continuing with destructive actions.

We also had to coordinate live monitoring, event normalization, post-run replay, and dashboard visualization while keeping the system modular and understandable.

### Accomplishments that we are proud of

We are proud to have built a working end-to-end prototype that connects an AI agent, a target application, an observation gateway, an evaluation engine, and a live dashboard.

Rangers can capture real security events, store them as reproducible run artifacts, and generate independent results based on observed evidence.

We are especially proud of separating Goal achievement from Rules of Engagement compliance. This makes it possible to identify agents that are capable of completing a task but are not sufficiently controlled or safe.

### What we learned

We learned that evaluating AI security agents requires more than checking their final answers.

A reliable evaluation must observe the complete interaction history and separate facts from interpretation. We also learned that security performance includes restraint. An agent should not only be capable of reaching a goal; it should also know when to stop and avoid actions outside its permitted scope.

We further learned the importance of reproducibility. Resetting the target environment and storing complete run artifacts makes it possible to compare different agents under consistent conditions.

### What's next for Rangers

Our next steps are to support more target applications, security scenarios, policies, and external AI agents.

We also plan to improve the dashboard with richer visualizations, larger-scale experiment comparison, and more detailed evidence exploration.

In the long term, Rangers could become a common evaluation layer for testing whether autonomous security agents are not only capable, but also verifiable, controlled, and responsible.

## Technologies Used

- Python
- FastAPI
- React
- TypeScript
- Vite
- Docker
- OWASP Juice Shop
- HTTP observation gateway
- Database observers
- JSON and JSONL event logs
- LLM providers and local model runtimes

## AI and External Tools Disclosure

AI tools were used for brainstorming, code assistance, documentation, test-scenario review, and UI refinement.

The final implementation was reviewed and tested by our team. We understand the project's architecture, source code, security evaluation methodology, and design decisions.

## Quick Start

Requirements: Python 3.11 or later, Docker Desktop, and an LLM API key or Ollama.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install -e .
```

Start the dashboard backend and frontend:

```bash
uvicorn console.backend.main:app --reload --port 8000
cd console/frontend
npm install
npm run dev
```

The dashboard is available at `http://localhost:5173`.

The core implementation uses the `ranger` Python package namespace. Existing scenario and artifact formats are designed for reproducible security-agent evaluation runs.
