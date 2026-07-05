"use strict";

const assert = require("node:assert/strict");
const { evaluateSessionRecording } = require("./index");

const baseRecording = {
  recordingId: "rec-enterprise-001",
  workspaceId: "institution-lab-7",
  actor: "admin@example.edu",
  events: [
    {
      id: "evt-1",
      type: "role_change",
      reason: "Temporary incident commander access",
      ticketId: "SEC-1842",
      reviewerApproval: "approval-771",
      contains: ["email"],
      redaction: { mode: "masked", evidenceId: "redact-evt-1" },
    },
    {
      id: "evt-2",
      type: "identity_provider_change",
      reason: "Rotate SAML signing certificate",
      ticketId: "IAM-390",
      reviewerApproval: "approval-772",
      contains: ["token"],
      redaction: { mode: "tokenized", evidenceId: "redact-evt-2" },
    },
  ],
  retention: { rawDays: 14, metadataDays: 365 },
  exportBundle: {
    auditDigestId: "audit-digest-1",
    redactionManifestId: "manifest-1",
    viewerAccessPolicyId: "policy-1",
  },
  share: {
    enabled: true,
    groups: ["security-reviewers", "compliance-auditors"],
    expiresInHours: 48,
  },
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

{
  const result = evaluateSessionRecording(baseRecording);
  assert.equal(result.decision, "release");
  assert.equal(result.auditPacket.exportReady, true);
  assert.equal(result.findings.length, 0);
}

{
  const recording = clone(baseRecording);
  delete recording.events[1].redaction;
  const result = evaluateSessionRecording(recording);
  assert.equal(result.decision, "hold");
  assert(result.findings.some((item) => item.code === "redaction.missing"));
}

{
  const recording = clone(baseRecording);
  recording.retention.rawDays = 90;
  const result = evaluateSessionRecording(recording);
  assert.equal(result.decision, "hold");
  assert(result.requiredActions.some((action) => action.includes("legal hold")));
}

{
  const recording = clone(baseRecording);
  delete recording.exportBundle.viewerAccessPolicyId;
  const result = evaluateSessionRecording(recording);
  assert.equal(result.decision, "revise");
  assert(result.findings.some((item) => item.code === "export.viewerAccessPolicyId.missing"));
}

{
  const recording = clone(baseRecording);
  recording.share.groups.push("all-staff");
  const result = evaluateSessionRecording(recording);
  assert.equal(result.decision, "hold");
  assert(result.findings.some((item) => item.code === "sharing.group.unapproved"));
}

console.log("enterprise admin session redaction guard tests passed");
