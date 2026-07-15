import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { emitOperationalEvent } from "../src/lib/operationalTelemetry.ts";

describe("safe operational telemetry", () => {
  it("emits a fixed-schema event with a generated opaque correlation id", () => {
    const lines: string[] = [];
    const eventId = emitOperationalEvent(
      "oauth_callback_failed",
      "persistence_unknown",
      (line) => lines.push(line),
    );

    assert.match(eventId, /^eoe_[A-Za-z0-9_-]{22}$/);
    assert.equal(lines.length, 1);
    const payload = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    assert.deepEqual(Object.keys(payload).sort(), ["event", "eventId", "outcome", "schema"]);
    assert.deepEqual(payload, {
      schema: "elmora-operational-v1",
      eventId,
      event: "oauth_callback_failed",
      outcome: "persistence_unknown",
    });
  });

  it("does not accept arbitrary metadata or exception details", () => {
    const source = emitOperationalEvent.toString();
    assert.doesNotMatch(source, /metadata|stack|message|error\s*:/i);
  });
});
