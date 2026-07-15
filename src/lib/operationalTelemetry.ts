import { randomBytes } from "node:crypto";

export type OperationalEventName =
  | "connect_session_create_unavailable"
  | "connect_session_resolve_unavailable"
  | "connect_session_status_unavailable"
  | "agent_registry_register_unavailable"
  | "agent_registry_revoke_unavailable"
  | "agent_runtime_status_unavailable"
  | "oauth_callback_failed"
  | "oauth_outcome_finalize_unavailable"
  | "readiness_check_failed";

export type OperationalOutcomeCode =
  | "dependency_unavailable"
  | "invalid_configuration"
  | "persistence_rejected"
  | "persistence_unknown"
  | "finalization_failed"
  | "authorization_revoked"
  | "internal_error";

type OperationalEventWriter = (line: string) => void;

export function emitOperationalEvent(
  event: OperationalEventName,
  outcome: OperationalOutcomeCode,
  write: OperationalEventWriter = console.error,
) {
  const eventId = `eoe_${randomBytes(16).toString("base64url")}`;
  write(
    JSON.stringify({
      schema: "elmora-operational-v1",
      eventId,
      event,
      outcome,
    }),
  );
  return eventId;
}

export function operationalErrorHeaders(
  event: OperationalEventName,
  outcome: OperationalOutcomeCode = "dependency_unavailable",
) {
  const eventId = emitOperationalEvent(event, outcome);
  return {
    "X-Elmora-Request-Id": eventId,
    "X-Elmora-Error-Code": event,
  };
}
