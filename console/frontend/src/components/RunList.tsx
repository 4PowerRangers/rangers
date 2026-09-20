import { useState } from "react";

type Run = {
  run_id: string; scenario?: string; status: string; error?: string; state?: string;
  step?: number; max_steps?: number; elapsed_sec?: number; steps?: number;
  tokens_total?: number; last_action?: string;
};
const TERMINAL_STATUSES = ["completed", "partial", "failed", "invalid"];
const labels: Record<string, string> = {
  running: "Live", completed: "Complete", partial: "Partial", failed: "Failed", invalid: "Invalid",
  resetting_target: "Resetting target",
};

export function RunList({
  runs,
  selected,
  select,
  stop,
  remove,
}: {
  runs: Run[];
  selected?: string;
  select: (r: Run) => void;
  stop: (r: Run) => void;
  remove: (r: Run) => void;
}) {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const visible = runs.filter(
    (r) =>
      (status === "all" || r.status === status) &&
      (!q ||
        `${r.scenario} ${r.run_id}`.toLowerCase().includes(q.toLowerCase())),
  );
  const progress = (run: Run) => {
    const step = run.step ?? run.steps ?? 0;
    return run.max_steps ? `${step}/${run.max_steps} steps` : `${step} steps`;
  };
  return (
    <>
      <div className="run-toolbar">
        <input
          aria-label="Search runs"
          placeholder="Search runs?"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <select
          aria-label="Filter runs by status"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="all">All statuses</option>
          <option value="running">Live</option>
          <option value="completed">Complete</option>
          <option value="partial">Partial</option>
          <option value="invalid">Invalid</option>
          <option value="failed">Failed</option>
        </select>
        <span>
          {visible.length} of {runs.length}
        </span>
      </div>
      <div className="run-list">
        {visible.length ? (
          visible.map((r) => (
            <div
              className={`run-item ${selected === r.run_id ? "selected" : ""}`}
              key={r.run_id}
              role="button"
              tabIndex={0}
              onClick={() => select(r)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") select(r);
              }}
            >
              <span className={`status-dot ${r.status}`} />
              <span className="run-copy">
                <strong>{r.scenario}</strong>
                {!TERMINAL_STATUSES.includes(r.status) && r.last_action ? (
                  <small title={r.last_action}>{r.last_action}</small>
                ) : (
                  <small title={r.run_id}>{r.run_id}</small>
                )}
              </span>
              <span className="run-stat">
                {progress(r)}
                {r.elapsed_sec != null && <small>{Math.round(r.elapsed_sec)}s elapsed</small>}
                {r.tokens_total != null && <small>{r.tokens_total} tokens</small>}
              </span>
              <span className={`status ${r.status}`} title={r.state || r.status}>
                {labels[r.status] || r.status}
                {r.state && r.state !== r.status && (
                  <small>{labels[r.state] || r.state.replace(/_/g, " ")}</small>
                )}
              </span>
              <span className="run-actions">
                {!TERMINAL_STATUSES.includes(r.status) && r.status !== "stopping" && (
                  <button
                    className="stop"
                    aria-label="Stop run"
                    title="Stop run"
                    onClick={(e) => {
                      e.stopPropagation();
                      stop(r);
                    }}
                  >
                    {String.fromCodePoint(0x23f9)}
                  </button>
                )}
                {r.status === "invalid" && (
                  <button
                    className="delete"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (confirm(`${r.run_id} invalid artifact? ??????`))
                        remove(r);
                    }}
                  >
                    delete
                  </button>
                )}
              </span>
              {r.status === "failed" && r.error && <small className="run-error">{r.error}</small>}
            </div>
          ))
        ) : (
          <p className="empty">No matching runs.</p>
        )}
      </div>
    </>
  );
}
