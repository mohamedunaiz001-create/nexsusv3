/** Every event name agents/events/event_bus.py publishes during a run.
 * Native EventSource requires a listener per named event (no wildcard),
 * so this list is what CEO AI Chat and the Agent Center subscribe to. */
export const KNOWN_EVENT_TYPES = [
  "ceo.plan_started",
  "ceo.plan_created",
  "ceo.delegated",
  "ceo.synthesis_started",
  "ceo.completed",
  "ceo.failed",
  "pipeline.batch_started",
  "task.state_changed",
  "agent.started",
  "agent.finished",
  "agent.attempt_failed",
  "agent.failed",
  "verification.started",
  "verification.passed",
  "verification.failed",
] as const;

export type OrchestrationEvent = {
  type: (typeof KNOWN_EVENT_TYPES)[number] | string;
  timestamp: string;
  [key: string]: any;
};
