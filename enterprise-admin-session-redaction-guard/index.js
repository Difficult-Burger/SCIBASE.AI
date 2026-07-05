"use strict";

const SENSITIVE_MARKERS = new Set([
  "api_key",
  "billing_account",
  "email",
  "embargoed_project",
  "password",
  "patient_identifier",
  "secret",
  "token",
]);

const CRITICAL_ACTIONS = new Set([
  "billing_export",
  "data_export",
  "identity_provider_change",
  "policy_change",
  "role_change",
]);

const ALLOWED_SHARE_GROUPS = new Set([
  "security-reviewers",
  "compliance-auditors",
  "incident-commanders",
]);

function evaluateSessionRecording(recording, options = {}) {
  const findings = [];
  const maxRawRetentionDays = options.maxRawRetentionDays ?? 30;
  const maxShareHours = options.maxShareHours ?? 72;

  requireField(recording, "recordingId", findings);
  requireField(recording, "workspaceId", findings);
  requireField(recording, "actor", findings);

  const events = Array.isArray(recording.events) ? recording.events : [];
  if (events.length === 0) {
    findings.push(finding("hold", "events.empty", "No admin-session events were provided."));
  }

  for (const event of events) {
    inspectSensitiveEvent(event, findings);
    inspectCriticalAction(event, findings);
  }

  inspectRetention(recording.retention || {}, maxRawRetentionDays, findings);
  inspectExportBundle(recording.exportBundle || {}, findings);
  inspectSharing(recording.share || {}, maxShareHours, findings);

  const severityRank = { info: 0, revise: 1, hold: 2 };
  const highest = findings.reduce((max, item) => Math.max(max, severityRank[item.severity]), 0);
  const decision = highest === 2 ? "hold" : highest === 1 ? "revise" : "release";
  const score = Math.max(0, 100 - findings.reduce((total, item) => total + (item.severity === "hold" ? 30 : 12), 0));

  return {
    decision,
    score,
    findings,
    requiredActions: findings
      .filter((item) => item.severity !== "info")
      .map((item) => item.action),
    auditPacket: {
      recordingId: recording.recordingId || "unknown",
      workspaceId: recording.workspaceId || "unknown",
      checkedAt: new Date("2026-07-05T00:00:00.000Z").toISOString(),
      sensitiveEventCount: events.filter((event) => hasSensitiveMarkers(event)).length,
      criticalActionCount: events.filter((event) => CRITICAL_ACTIONS.has(event.type)).length,
      exportReady: decision === "release",
    },
  };
}

function requireField(recording, field, findings) {
  if (!recording || !recording[field]) {
    findings.push(finding("revise", `recording.${field}.missing`, `Missing ${field}.`));
  }
}

function inspectSensitiveEvent(event, findings) {
  const markers = sensitiveMarkers(event);
  if (markers.length === 0) return;

  if (!event.redaction || !["masked", "tokenized"].includes(event.redaction.mode)) {
    findings.push(finding(
      "hold",
      "redaction.missing",
      `Event ${event.id || event.type || "unknown"} exposes sensitive markers: ${markers.join(", ")}.`,
      "Mask or tokenize all sensitive fields before session replay can be exported."
    ));
  }

  if (!event.redaction || !event.redaction.evidenceId) {
    findings.push(finding(
      "revise",
      "redaction.evidence.missing",
      `Event ${event.id || event.type || "unknown"} lacks redaction evidence.`,
      "Attach a redaction evidence id for auditor traceability."
    ));
  }
}

function inspectCriticalAction(event, findings) {
  if (!CRITICAL_ACTIONS.has(event.type)) return;

  if (!event.reason || !event.ticketId) {
    findings.push(finding(
      "hold",
      "critical_action.context.missing",
      `Critical action ${event.type} lacks reason or ticket id.`,
      "Add a business reason and linked ticket for the privileged action."
    ));
  }

  if (!event.reviewerApproval) {
    findings.push(finding(
      "revise",
      "critical_action.approval.missing",
      `Critical action ${event.type} lacks reviewer approval evidence.`,
      "Attach reviewer approval before sharing the replay with enterprise auditors."
    ));
  }
}

function inspectRetention(retention, maxRawRetentionDays, findings) {
  if (typeof retention.rawDays !== "number") {
    findings.push(finding("revise", "retention.raw_days.missing", "Raw playback retention is not declared."));
    return;
  }

  if (retention.rawDays > maxRawRetentionDays && !retention.legalHoldId) {
    findings.push(finding(
      "hold",
      "retention.raw_days.too_long",
      `Raw playback retention is ${retention.rawDays} days without legal hold.`,
      `Reduce raw playback retention to ${maxRawRetentionDays} days or attach a legal hold id.`
    ));
  }
}

function inspectExportBundle(bundle, findings) {
  for (const field of ["auditDigestId", "redactionManifestId", "viewerAccessPolicyId"]) {
    if (!bundle[field]) {
      findings.push(finding(
        "revise",
        `export.${field}.missing`,
        `Export bundle is missing ${field}.`,
        "Include a complete export bundle for enterprise review."
      ));
    }
  }
}

function inspectSharing(share, maxShareHours, findings) {
  if (!share.enabled) return;

  const groups = Array.isArray(share.groups) ? share.groups : [];
  const unknownGroups = groups.filter((group) => !ALLOWED_SHARE_GROUPS.has(group));
  if (unknownGroups.length > 0) {
    findings.push(finding(
      "hold",
      "sharing.group.unapproved",
      `Replay shared with unapproved groups: ${unknownGroups.join(", ")}.`,
      "Restrict replay sharing to approved security, compliance, or incident groups."
    ));
  }

  if (typeof share.expiresInHours !== "number" || share.expiresInHours > maxShareHours) {
    findings.push(finding(
      "revise",
      "sharing.expiry.invalid",
      "Replay share expiry is missing or too long.",
      `Set replay sharing expiry to ${maxShareHours} hours or less.`
    ));
  }
}

function sensitiveMarkers(event) {
  const markers = Array.isArray(event.contains) ? event.contains : [];
  return markers.filter((marker) => SENSITIVE_MARKERS.has(marker));
}

function hasSensitiveMarkers(event) {
  return sensitiveMarkers(event).length > 0;
}

function finding(severity, code, message, action = "Update the session recording package and rerun the guard.") {
  return { severity, code, message, action };
}

module.exports = {
  evaluateSessionRecording,
  SENSITIVE_MARKERS,
  CRITICAL_ACTIONS,
};
