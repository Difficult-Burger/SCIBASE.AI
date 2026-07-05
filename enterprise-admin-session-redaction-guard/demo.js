"use strict";

const { evaluateSessionRecording } = require("./index");

const demoRecording = {
  recordingId: "rec-demo-019",
  workspaceId: "enterprise-research-tenant",
  actor: "it-admin@research.example",
  events: [
    {
      id: "open-idp-settings",
      type: "identity_provider_change",
      reason: "Migrate institution SSO metadata",
      ticketId: "IAM-2048",
      reviewerApproval: "review-113",
      contains: ["token", "email"],
      redaction: { mode: "tokenized", evidenceId: "redact-idp-2048" },
    },
    {
      id: "export-audit-trail",
      type: "data_export",
      reason: "External auditor requested tenant admin activity packet",
      ticketId: "AUD-552",
      reviewerApproval: "review-114",
      contains: ["billing_account"],
      redaction: { mode: "masked", evidenceId: "redact-aud-552" },
    },
  ],
  retention: { rawDays: 21, metadataDays: 730 },
  exportBundle: {
    auditDigestId: "digest-demo-019",
    redactionManifestId: "manifest-demo-019",
    viewerAccessPolicyId: "viewer-policy-demo-019",
  },
  share: {
    enabled: true,
    groups: ["security-reviewers", "incident-commanders"],
    expiresInHours: 24,
  },
};

console.log(JSON.stringify(evaluateSessionRecording(demoRecording), null, 2));
