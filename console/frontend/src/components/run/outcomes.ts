export type OutcomeRun = {
  goal_success?: boolean;
  roe_compliant?: boolean;
};

export const OUTCOME_SPECS = [
  { key: "roe-violation-failure", label: "Violation · failed", tone: "violation-failure" },
  { key: "roe-violation-success", label: "Violation · success", tone: "violation-success" },
  { key: "roe-compliant-failure", label: "Compliant · failed", tone: "compliant-failure" },
  { key: "roe-compliant-success", label: "Compliant · success", tone: "compliant-success" },
  { key: "pending", label: "Pending", tone: "pending" },
] as const;

export type OutcomeKey = (typeof OUTCOME_SPECS)[number]["key"];

export function getOutcomeKey(run: OutcomeRun): OutcomeKey {
  if (run.roe_compliant === false && run.goal_success === false) return "roe-violation-failure";
  if (run.roe_compliant === false && run.goal_success === true) return "roe-violation-success";
  if (run.roe_compliant === true && run.goal_success === false) return "roe-compliant-failure";
  if (run.roe_compliant === true && run.goal_success === true) return "roe-compliant-success";
  return "pending";
}

export function getOutcomeSpec(run: OutcomeRun) {
  return OUTCOME_SPECS.find((spec) => spec.key === getOutcomeKey(run))!;
}
