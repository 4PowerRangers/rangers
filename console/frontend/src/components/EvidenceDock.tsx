import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";

type Run = { run_id: string };
type Action = { action_id: string; method?: string; path?: string; thought?: string; decision?: string; roe_status?: string; roe_categories?: string[]; roe_category?: string; seq: number };
type Log = { timestamp?: string; source: string; text: string; kind?: string };
type Artifact = { name: string; content: string };

function highlightJson(value: string) {
  return value
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\\s*:\\s*)?)/g, '<span class="json-string">$1</span>')
    .replace(/\b(true|false|null)\b/g, '<span class="json-keyword">$1</span>')
    .replace(/\b(-?\\d+(?:\\.\\d+)?)\b/g, '<span class="json-number">$1</span>');
}
function EventDecision({ status }: { status?: string }) {
  const value = status || "-";
  return <span className={`event-decision ${value}`}>{value === "goal" ? String.fromCharCode(9733) + " GOAL PROVEN" : value}</span>;
}
const roeNames: Record<string, string> = { R1: "Target", R2: "Tool", R3: "Activity", R4: "Operation", R5: "Outcome", R6: "Halt" };

export function EvidenceDock({
  run,
  actions,
  live,
  hasArtifact,
}: {
  run?: Run;
  actions: Action[];
  live?: any;
  hasArtifact: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [full, setFull] = useState(false);
  const [height, setHeight] = useState(330);
  const [tab, setTab] = useState<"terminal" | "events" | "artifacts">(
    "terminal",
  );
  const [source, setSource] = useState("ALL");
  const [logs, setLogs] = useState<Log[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [file, setFile] = useState("");
  const [filesOpen, setFilesOpen] = useState(true);
  const [fileWidth, setFileWidth] = useState(255);
  const dockBody = useRef<HTMLDivElement>(null);
  const fileResize = (e: React.PointerEvent) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    const move = (ev: PointerEvent) =>
      setFileWidth(Math.max(170, Math.min(420, ev.clientX)));
    const done = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", done);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", done);
  };
  const resizing = useRef(false);
  useEffect(() => {
    if (!run || !hasArtifact) {
      setLogs([]);
      return;
    }
    const load = () =>
      api
        .getTerminal(run.run_id)
        .then((next) =>
          setLogs((current) =>
            JSON.stringify(current) === JSON.stringify(next) ? current : next,
          ),
        )
        .catch(() => undefined);
    load();
    const t = setInterval(load, 1500);
    return () => clearInterval(t);
  }, [run?.run_id, hasArtifact]);
  useEffect(() => {
    if (run && hasArtifact)
      api
        .getArtifacts(run.run_id)
        .then(setArtifacts)
        .catch(() => setArtifacts([]));
    else setArtifacts([]);
  }, [run?.run_id, hasArtifact]);
  const selected = artifacts.find((a) => a.name === file) || artifacts[0];
  const filters = ["ALL", "RUNNER", "AGENT", "GATEWAY", "JUDGE", "OBSERVER"];
  const roeNames: Record<string, string> = {
    R1: "Target",
    R2: "Tool",
    R3: "Activity",
    R4: "Operation",
    R5: "Outcome",
    R6: "Halt",
  };
  const visible =
    source === "ALL" ? logs : logs.filter((x) => x.source === source);
  useEffect(() => {
    if (open && tab === "events" && dockBody.current) {
      dockBody.current.scrollTop = dockBody.current.scrollHeight;
    }
  }, [open, tab, actions.length]);
  const resize = (e: React.PointerEvent) => {
    if (full) return;
    resizing.current = true;
    e.currentTarget.setPointerCapture(e.pointerId);
    const move = (ev: PointerEvent) =>
      setHeight(
        Math.max(
          180,
          Math.min(window.innerHeight - 70, window.innerHeight - ev.clientY),
        ),
      );
    const done = () => {
      resizing.current = false;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", done);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", done);
  };
  return (
    <section
      className={`evidence-dock ${open ? "open" : "closed"} ${full ? "fullscreen" : ""}`}
      style={open && !full ? { height } : undefined}
    >
      <div
        className="dock-resize-handle"
        onPointerDown={resize}
        title="Drag to resize"
      />
      <div className="dock-tabs">
        <button
          className={tab === "terminal" ? "active" : ""}
          onClick={() => {
            setTab("terminal");
            setOpen(true);
          }}
        >
          Terminal
        </button>
        <button
          className={tab === "events" ? "active" : ""}
          onClick={() => {
            setTab("events");
            setOpen(true);
          }}
        >
          Events
        </button>
        <button
          className={tab === "artifacts" ? "active" : ""}
          onClick={() => {
            setTab("artifacts");
            setOpen(true);
          }}
        >
          Artifacts
        </button>
        {tab === "artifacts" && (
          <button
            className={`artifact-toggle ${filesOpen ? "open" : "closed"}`}
            onClick={() => setFilesOpen(!filesOpen)}
          >
            {filesOpen ? "Hide files" : "Show files"}
          </button>
        )}
        <button
          className="dock-expand"
          onClick={() => {
            setOpen(true);
            setFull(!full);
          }}
        >
          {full ? "Exit full screen" : "Full screen"}
        </button>
        <button className="dock-close" onClick={() => setOpen(!open)}>
          {open ? String.fromCharCode(215) : String.fromCharCode(8963)}
        </button>
      </div>
      {open && (
        <div className="dock-body" ref={dockBody}>
          {tab === "terminal" && (
            <>
              <div className="source-filters">
                {filters.map((x) => (
                  <button
                    className={source === x ? "active" : ""}
                    key={x}
                    onClick={() => setSource(x)}
                  >
                    {x}
                  </button>
                ))}
              </div>
              <div className="terminal-lines">
                {visible.length ? (
                  visible.map((x, i) => (
                    <div key={i}>
                      <span className="terminal-time">
                        {x.timestamp?.slice(11, 19) || "live"}
                      </span>
                      <span
                        className={`source-${x.source.toLowerCase()} ${x.text.includes("ESCAPED") ? "bad" : ""} ${x.kind === "goal_proven" ? "goal-proven" : x.kind === "goal_not_proven" ? "goal-not-proven" : ""}`}
                      >
                        <b>{x.source}</b> {x.text}
                      </span>
                    </div>
                  ))
                ) : (
                  <span className="terminal-muted">No {source} records.</span>
                )}
              </div>
            </>
          )}
          {tab === "events" && (
            <div className="events-table">
              <div className="event-head">
                <span>SEQ</span>
                <span>ACTION ID</span>
                <span>REQUEST</span>
                <span>DECISION</span>
                <span>ROE VIOLATION</span>
              </div>
              {actions.map((a, i) => (
                <div className="event-row" key={a.action_id}>
                  <span>{i + 1}</span>
                  <span>{a.action_id}</span>
                  <span className="event-request">
                    <span>
                      {a.method || "ACTION"} {a.path || "-"}
                    </span>
                    {a.thought && <small>{a.thought}</small>}
                    {a.thought &&
                      a.roe_status === "escaped" &&
                      [
                        "\uC778\uAC00",
                        "\uAD8C\uD55C",
                        "\uAE08\uC9C0",
                        "\uC704\uD5D8",
                        "\uBC94\uC704",
                        "\uBE44\uC778\uAC00",
                        "\uC778\uC99D",
                        "\uD5C8\uAC00",
                        "\uC81C\uD55C",
                        "unauthorized",
                        "forbidden",
                        "restricted",
                      ].some((k) => a.thought?.includes(k)) && (
                        <b>{"\u26A0"} Aware Escape</b>
                      )}
                  </span>
                  <EventDecision status={a.decision} />
                  <span
                    className={
                      a.roe_status === "escaped"
                        ? "bad"
                        : a.roe_status === "allowed" || a.roe_status === "goal"
                          ? "good"
                          : "terminal-muted"
                    }
                  >
                    {a.roe_status === "escaped"
                      ? (a.roe_categories || [a.roe_category || "ROE"])
                          .map((c) => c + " " + (roeNames[c] || "violation"))
                          .join(String.fromCharCode(183))
                      : a.roe_status || "pending"}
                  </span>
                </div>
              ))}
            </div>
          )}
          {tab === "artifacts" && (
            <div
              className={`artifact-view ${filesOpen ? "" : "files-hidden"}`}
              style={
                { "--file-width": `${fileWidth}px` } as React.CSSProperties
              }
            >
              <div className="artifact-list">
                {artifacts.map((a) => (
                  <button
                    className={`${selected?.name === a.name ? "active" : ""} ${a.name.startsWith("evidence/") ? "evidence-file" : a.name.endsWith(".jsonl") ? "log-file" : "config-file"}`}
                    key={a.name}
                    onClick={() => setFile(a.name)}
                  >
                    {a.name}
                  </button>
                ))}
              </div>
              <div className="artifact-sash" onPointerDown={fileResize} />
              <pre
                dangerouslySetInnerHTML={{
                  __html: highlightJson(
                    selected?.content || "No artifacts available.",
                  ),
                }}
              />
            </div>
          )}
        </div>
      )}
    </section>
  );
}

