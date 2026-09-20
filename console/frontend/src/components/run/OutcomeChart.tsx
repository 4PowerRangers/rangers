import { OUTCOME_SPECS, getOutcomeKey } from "./outcomes";

export type OutcomeRun = {
  run_id: string;
  scenario?: string;
  status: string;
  goal_success?: boolean;
  roe_compliant?: boolean;
};

type Props = {
  runs: OutcomeRun[];
  mode: "count" | "ratio";
  onRunClick: (run: OutcomeRun) => void;
};

export function OutcomeChart({ runs, mode }: Props) {
  const rows = [...new Set(runs.map((run) => run.scenario || "Unknown scenario"))]
    .map((scenario) => {
      const scenarioRuns = runs.filter((run) => (run.scenario || "Unknown scenario") === scenario);
      return { scenario, runs: scenarioRuns, counts: Object.fromEntries(OUTCOME_SPECS.map((spec) => [spec.key, scenarioRuns.filter((run) => getOutcomeKey(run) === spec.key).length])) as Record<string, number> };
    })
    .sort((a, b) => b.runs.length - a.runs.length);
  const max = mode === "count" ? Math.max(...rows.map((row) => row.runs.length), 1) : 100;

  return <div className="outcome-chart-module">
    <div className="outcome-controls"><div className="outcome-legend">{OUTCOME_SPECS.map((spec) => <span key={spec.key} className={spec.tone}><i />{spec.label}</span>)}</div><span className="outcome-chart-total">{runs.length} total runs</span></div>
    <div className="outcome-scenario-chart">
      {rows.map((row) => <div key={row.scenario} className="outcome-scenario-row">
        <div className="outcome-scenario-name"><strong>{row.scenario}</strong><small>{row.runs.length} runs</small></div>
        <div className="outcome-stack">{OUTCOME_SPECS.map((spec) => { const count = row.counts[spec.key] || 0; const value = mode === "count" ? count : (row.runs.length ? (count / row.runs.length) * 100 : 0); return <span key={spec.key} className={spec.tone} style={{ width: `${(value / max) * 100}%` }} />; })}</div>
        <b className="outcome-scenario-total">{mode === "count" ? row.runs.length : "100%"}<small>n={row.runs.length}</small></b>
      </div>)}
    </div>
  </div>;
}
