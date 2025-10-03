import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import "./App.css";

type Verdict = "phishing" | "suspicious" | "legitimate";

type RiskSignal = {
  feature: string;
  message: string;
  impact: number;
  evidence?: string | null;
};

type FeatureVectorItem = {
  name: string;
  value: number;
  weight: number;
  impact: number;
  description: string;
  evidence?: string | null;
};

type Analysis = {
  normalizedUrl: string;
  score: number;
  verdict: Verdict;
  confidence: number;
  signals: RiskSignal[];
  featureVector: FeatureVectorItem[];
  recommendations: string[];
};

const sampleAnalysis: Analysis = {
  normalizedUrl: "http://192.64.12.11/account-verify",
  score: 0.86,
  verdict: "phishing",
  confidence: 0.72,
  signals: [
    {
      feature: "has_ip_address",
      impact: 1.6,
      message: "Domain is a direct IP address instead of a hostname.",
      evidence: "Host '192.64.12.11'",
    },
    {
      feature: "content_keyword_risk",
      impact: 1.04,
      message: "Page copy heavily uses sensitive terms.",
      evidence: "update, password, urgent",
    },
    {
      feature: "missing_https",
      impact: 1.1,
      message: "Site does not use HTTPS, reducing authenticity.",
      evidence: "Scheme 'http'",
    },
  ],
  featureVector: [
    {
      name: "has_ip_address",
      value: 1,
      weight: 1.6,
      impact: 1.6,
      description: "Domain is a direct IP address instead of a hostname.",
      evidence: "Host '192.64.12.11'",
    },
    {
      name: "missing_https",
      value: 1,
      weight: 1.1,
      impact: 1.1,
      description: "Site does not use HTTPS, reducing authenticity.",
      evidence: "Scheme 'http'",
    },
    {
      name: "content_keyword_risk",
      value: 0.8,
      weight: 1.3,
      impact: 1.04,
      description: "Page copy heavily uses sensitive terms.",
      evidence: "update, password, urgent",
    },
  ],
  recommendations: [
    "Do not enter credentials or personal information on this site.",
    "Verify the sender or URL by contacting the organization through a known channel.",
    "Report the site to your security team or email provider.",
  ],
};

const verdictCopy: Record<Verdict, { label: string; tone: string }> = {
  phishing: { label: "High Risk", tone: "danger" },
  suspicious: { label: "Needs Review", tone: "warning" },
  legitimate: { label: "Looks Safe", tone: "success" },
};

const verdictDescription: Record<Verdict, string> = {
  phishing:
    "Multiple high-risk signals detected. Treat this URL as malicious and alert your security team.",
  suspicious:
    "A few cautionary indicators were found. Verify the sender manually before clicking or sharing.",
  legitimate:
    "No strong risk signals found, but continue practicing healthy security hygiene.",
};

const verdictGaugeColor: Record<Verdict, string> = {
  phishing: "#ff5c8d",
  suspicious: "#f59e0b",
  legitimate: "#22c55e",
};

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

function formatPercent(value: number) {
  return `${Math.round(value * 100)}%`;
}

function App() {
  const [url, setUrl] = useState("");
  const [html, setHtml] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scoreStyle = useMemo(() => {
    const safeScore = analysis?.score ?? 0;
    const gaugeColor = analysis
      ? verdictGaugeColor[analysis.verdict]
      : "#4f46e5";
    return {
      "--score": `${Math.round(safeScore * 100)}`,
      "--gauge-color": gaugeColor,
    } as React.CSSProperties;
  }, [analysis?.score, analysis?.verdict]);

  const verdictTone = analysis ? verdictCopy[analysis.verdict] : null;

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Enter a URL to analyze.");
      return;
    }

    const normalizedUrl = trimmed.match(/^https?:\/\//i)
      ? trimmed
      : `https://${trimmed}`;
    setIsSubmitting(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: normalizedUrl,
          html: html.trim() ? html : null,
        }),
      });

      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Analysis request failed");
      }

      const payload = (await response.json()) as Analysis;
      setAnalysis(payload);
    } catch (cause) {
      const message =
        cause instanceof Error ? cause.message : "Unexpected error";
      setError(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUseSample = () => {
    setAnalysis(sampleAnalysis);
    setUrl("192.64.12.11/account-verify");
    setHtml(
      "<html><body><h2>Account Alert</h2><p>Please update your password immediately to avoid suspension.</p><form><input placeholder='Email' /></form></body></html>"
    );
    setError(null);
  };

  return (
    <div className="app-shell">
      <div className="app-background" />
      <main className="app-content">
        <header className="hero">
          <span className="hero__badge">AI-powered security assistant</span>
          <h1>PhishGuard Intelligence</h1>
          <p>
            Paste a suspicious URL or capture from a suspected phishing email.
            Our heuristic AI engine highlights risky signals, confidence, and
            next steps.
          </p>
          <div className="hero__meta">
            <div>
              <strong>0.1s avg</strong>
              <span>processing time</span>
            </div>
            <div>
              <strong>11</strong>
              <span>heuristic checks</span>
            </div>
            <div>
              <strong>3 tiers</strong>
              <span>risk verdicts</span>
            </div>
          </div>
        </header>

        <section className="layout">
          <article className="panel form-card">
            <div className="panel__header">
              <h2>Run an analysis</h2>
              <p>
                Feed the detector a URL, optionally paste captured HTML to
                sharpen the signals.
              </p>
            </div>
            <form className="analysis-form" onSubmit={handleSubmit}>
              <label htmlFor="url">Suspicious URL</label>
              <div className="input-group">
                <span className="input-prefix">https://</span>
                <input
                  id="url"
                  type="text"
                  placeholder="example-company-security.com/login"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  required
                />
              </div>

              <label htmlFor="html">HTML or email content (optional)</label>
              <textarea
                id="html"
                placeholder="Paste raw HTML or the suspicious email copy to extract more context..."
                value={html}
                onChange={(event) => setHtml(event.target.value)}
                rows={8}
              />

              <div className="form-actions">
                <button
                  className="btn btn-primary"
                  type="submit"
                  disabled={isSubmitting}
                >
                  {isSubmitting ? "Scanning…" : "Analyze URL"}
                </button>
                <button
                  className="btn btn-ghost"
                  type="button"
                  onClick={handleUseSample}
                >
                  Use sample data
                </button>
              </div>
              {error && <p className="form-error">{error}</p>}
            </form>
          </article>

          <article className="panel result-card">
            <div className="panel__header">
              <h2>Risk intelligence</h2>
              <p>
                Interpretations grounded in heuristic scoring and contextual
                signals.
              </p>
            </div>

            {analysis ? (
              <div className="analysis-output">
                <div className="analysis-summary">
                  <div className="gauge" style={scoreStyle}>
                    <span className="gauge__value">
                      {analysis.score.toFixed(2)}
                      <small>score</small>
                    </span>
                  </div>
                  <div>
                    <span
                      className={`verdict-badge verdict-badge--${verdictTone?.tone}`}
                    >
                      {verdictTone?.label}
                    </span>
                    <h3>{analysis.verdict.toUpperCase()}</h3>
                    <p>{verdictDescription[analysis.verdict]}</p>
                    <dl className="meta">
                      <div>
                        <dt>Normalized URL</dt>
                        <dd>{analysis.normalizedUrl}</dd>
                      </div>
                      <div>
                        <dt>Confidence</dt>
                        <dd>{formatPercent(analysis.confidence)}</dd>
                      </div>
                    </dl>
                  </div>
                </div>

                <section className="signals">
                  <h4>Key signals</h4>
                  {analysis.signals.length === 0 ? (
                    <p className="empty">No strong risk signals surfaced.</p>
                  ) : (
                    <ul>
                      {analysis.signals.map((signal) => (
                        <li key={signal.feature}>
                          <div>
                            <strong>{signal.message}</strong>
                            {signal.evidence ? (
                              <span>{signal.evidence}</span>
                            ) : null}
                          </div>
                          <span className="impact">
                            Impact {signal.impact.toFixed(2)}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>

                <section className="recommendations">
                  <h4>Recommended next steps</h4>
                  <ol>
                    {analysis.recommendations.map((tip, index) => (
                      <li key={index}>{tip}</li>
                    ))}
                  </ol>
                </section>

                {analysis.featureVector.length > 0 && (
                  <section className="feature-breakdown">
                    <h4>Signal weights</h4>
                    <div className="feature-grid">
                      {analysis.featureVector.slice(0, 8).map((feature) => (
                        <div key={feature.name} className="feature-card">
                          <header>
                            <span className="feature-name">{feature.name}</span>
                            <span className="feature-impact">
                              Impact {feature.impact.toFixed(2)}
                            </span>
                          </header>
                          <p>{feature.description}</p>
                          <dl>
                            <div>
                              <dt>Value</dt>
                              <dd>{feature.value.toFixed(2)}</dd>
                            </div>
                            <div>
                              <dt>Weight</dt>
                              <dd>{feature.weight}</dd>
                            </div>
                          </dl>
                          {feature.evidence ? (
                            <footer>{feature.evidence}</footer>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  </section>
                )}
              </div>
            ) : (
              <div className="analysis-placeholder">
                <h3>No analysis yet</h3>
                <p>
                  Start by pasting a suspicious URL. We'll decode the domain,
                  structure, and wording immediately.
                </p>
                <button
                  className="btn btn-ghost"
                  type="button"
                  onClick={handleUseSample}
                >
                  Preview sample report
                </button>
              </div>
            )}
          </article>
        </section>
      </main>
    </div>
  );
}

export default App;
