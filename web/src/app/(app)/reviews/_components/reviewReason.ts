// Maps the backend's coded hold reason (ReviewView.review_reason /
// MessageView.review_reason) to the reader-friendly line shown in the review
// queue. The API value is an OPEN set — new codes may appear before the UI
// knows them — so unknown codes fall back to a humanized form rather than being
// dropped. Known codes mirror internal/identity/screening.go.
const REVIEW_REASON_LABELS: Record<string, string> = {
  sender_gate: "Sender blocked by inbound policy",
  recipient_gate: "Recipient blocked by outbound policy",
  inbound_scan: "Content flagged by screening scan",
  outbound_scan: "Content flagged by screening scan",
  outbound_send: "Outbound send blocked",
};

// Humanize an unknown coded value: "some_new_reason" / "some-new-reason" →
// "Some new reason".
function humanizeCode(code: string): string {
  const spaced = code.replace(/[_-]/g, " ").trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

// Friendly labels for detector threat categories (protection_events). Open set —
// a category the UI doesn't know yet is humanized, not dropped.
const THREAT_CATEGORY_LABELS: Record<string, string> = {
  "prompt-injection": "Prompt injection",
  jailbreak: "Jailbreak attempt",
  "data-exfiltration": "Data exfiltration",
  "credential-phishing": "Credential phishing",
  phishing: "Phishing",
  malware: "Malware",
  "social-engineering": "Social engineering",
};

// categoryLabel maps a detector category name to a reader-friendly label,
// tolerating both "prompt-injection" and "prompt_injection" spellings. typeof
// guard (not `?? `) so a name colliding with an Object.prototype key can't
// resolve to an inherited member.
export function categoryLabel(name: string): string {
  const key = name.toLowerCase().replace(/_/g, "-");
  const mapped = THREAT_CATEGORY_LABELS[key];
  return typeof mapped === "string" ? mapped : humanizeCode(name);
}

// A scan finding shape from ProtectionFinding[] (kept structural to avoid a
// cross-module type import).
type ScanFinding = {
  source: string;
  action?: string;
  score?: number | null;
  categories?: { name: string; score?: number }[];
  summary?: string;
};

// protectionHeadline distills the review-detail protection breakdown into the
// one-line "why held" shown in the expanded row: the highest-confidence scan
// category + the detector's rationale (e.g. "Prompt injection — instructs the
// agent to wire funds"). Returns null when there is no scan detail to show
// (gate-only holds, or the detail hasn't loaded) so the caller falls back to the
// coarse review_reason label.
export function protectionHeadline(
  findings?: ScanFinding[] | null,
): { category: string; summary?: string; score?: number | null } | null {
  if (!findings || findings.length === 0) return null;
  const scan = findings.find(
    (f) =>
      f.source === "scan" && ((f.categories?.length ?? 0) > 0 || !!f.summary),
  );
  if (!scan) return null;
  const top = scan.categories
    ?.slice()
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];
  return {
    category: top ? categoryLabel(top.name) : "Content flagged by screening scan",
    summary: scan.summary,
    // The score shown next to the category label is THAT category's confidence,
    // not the finding-level aggregate — otherwise the number could contradict
    // the label. Falls back to the finding score when the category has none.
    score: top?.score ?? scan.score,
  };
}

// Builds the "why held" line for a review row. Returns null when there is no
// reason to show (so callers can omit the element entirely). `score` — the
// aggregate content-scan confidence (0..1), present only for scan holds — is
// appended as a parenthetical when available.
export function reviewReasonLabel(
  reason?: string | null,
  score?: number | null,
): string | null {
  if (!reason) return null;
  // typeof guard, not `?? humanizeCode`: REVIEW_REASON_LABELS is a plain object,
  // so a coded reason that collides with an Object.prototype key ("constructor",
  // "toString", …) would otherwise resolve to an inherited function/object and
  // crash the React render. review_reason is server-assigned from a fixed set
  // today, but the field is documented open-set, so stay defensive.
  const mapped = REVIEW_REASON_LABELS[reason];
  const base = typeof mapped === "string" ? mapped : humanizeCode(reason);
  if (typeof score === "number" && Number.isFinite(score)) {
    return `${base} (${score.toFixed(2)})`;
  }
  return base;
}
