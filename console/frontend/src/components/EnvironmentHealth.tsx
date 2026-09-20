import { useEffect, useState } from "react";
import { api } from "../api/client";

export function EnvironmentHealth() {
  const [state, setState] = useState<any>();
  const [starting, setStarting] = useState(false);
  const [message, setMessage] = useState("");
  const healthChecks = [
    ["target", "Target"],
    ["model_relay", "Model relay"],
  ] as const;

  useEffect(() => {
    const load = () =>
      api
        .getEnvStatus()
        .then(setState)
        .catch(() => setState(undefined));
    load();
    const timer = setInterval(load, 2000);
    return () => clearInterval(timer);
  }, []);

  const startEnvironment = () => {
    setStarting(true);
    setMessage("");
    api.startEnvironment().then(() => setMessage("started")).catch((e) => setMessage(e.message)).finally(() => setStarting(false));
  };
  const healthy = state
    ? healthChecks.filter(([key]) => state[key]?.status === "ready").length
    : 0;

  return (
    <section className="environment-health" aria-label="Environment health">
      <div className="health-heading">
        <strong>Environment</strong>
        <span>{state ? `${healthy}/${healthChecks.length} healthy` : "checking?"}</span>
        <button className="environment-start" onClick={startEnvironment} disabled={starting}>{starting ? "Starting..." : "Start environment"}</button>
      </div>
      {message && <small className="environment-message">{message}</small>}
      <div className="health-grid">
        {healthChecks.map(([key, name]) => {
          const item = state?.[key] || { status: "checking" };
          const healthLabel = `${name}: ${String(item.status).replace(/_/g, " ")}${
            item.latency_ms != null ? ` (${item.latency_ms} ms)` : ""
          }`;
          return (
            <div
              className={`health-item ${item.status}`}
              key={key}
              data-tooltip={healthLabel}
              aria-label={healthLabel}
              tabIndex={0}
            >
              <i />
              <span>{name}</span>
              <b>{item.status.replace("_", " ")}</b>
              {item.latency_ms != null && <small>{item.latency_ms} ms</small>}
            </div>
          );
        })}
      </div>
    </section>
  );
}
