import Link from "next/link";

const workers = [
  {
    title: "Inbox operations",
    body: "Prioritize messages, draft replies, surface urgent requests, and keep handoffs clear.",
  },
  {
    title: "Booking coordination",
    body: "Help customers schedule, reschedule, and confirm appointments without adding admin load.",
  },
  {
    title: "Back-office follow-through",
    body: "Track routine tasks, prepare summaries, and keep business workflows moving in the background.",
  },
];

export default function Home() {
  return (
    <main>
      <section className="container hero">
        <div>
          <p className="eyebrow">Managed AI workers for real operations</p>
          <h1>Delegate the inbox, booking, and back office.</h1>
          <p className="lede">
            Elmora runs hosted AI workers that help small teams keep up with customer communication,
            scheduling, and operational follow-through — with human oversight where it matters.
          </p>
          <div className="cta-row">
            <Link className="button primary" href="/connect/google">
              Preview Google Connect
            </Link>
            <Link className="button" href="/#workers">
              See worker types
            </Link>
          </div>
          <div className="trust-row" aria-label="Elmora operating principles">
            <div className="metric"><strong>Hosted</strong><span>Managed setup and monitoring</span></div>
            <div className="metric"><strong>Practical</strong><span>Built for daily admin work</span></div>
            <div className="metric"><strong>Secure</strong><span>No secrets stored in code</span></div>
          </div>
        </div>
        <aside className="panel" aria-label="Example Elmora worker status">
          <div className="worker-card">
            <p className="eyebrow">Worker queue</p>
            <div className="worker-row"><strong>Inbox triage</strong><span className="status">Ready</span></div>
            <div className="worker-row"><strong>Booking follow-up</strong><span>Awaiting calendar</span></div>
            <div className="worker-row"><strong>Daily ops digest</strong><span>Scheduled</span></div>
            <div className="worker-row"><strong>Human review</strong><span>Required for sends</span></div>
          </div>
        </aside>
      </section>

      <section className="container section" id="workers">
        <div className="section-heading">
          <h2>AI workers for the work between tools.</h2>
          <p>
            Elmora is designed for operational tasks that are repetitive, context-heavy, and too
            important to leave unmanaged.
          </p>
        </div>
        <div className="grid-3">
          {workers.map((worker) => (
            <article className="card" key={worker.title}>
              <h3>{worker.title}</h3>
              <p>{worker.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="container section">
        <div className="section-heading">
          <h2>Simple path to managed automation.</h2>
          <p>Start with a connected account, define the work, then review outcomes before expanding scope.</p>
        </div>
        <div className="steps">
          <div className="step">
            <div>
              <h3>Connect the right workspace</h3>
              <p>Use a hosted OAuth flow for Gmail, Calendar, and future workspace integrations.</p>
            </div>
          </div>
          <div className="step">
            <div>
              <h3>Configure worker boundaries</h3>
              <p>Define what the worker can read, draft, summarize, schedule, or escalate.</p>
            </div>
          </div>
          <div className="step">
            <div>
              <h3>Operate with oversight</h3>
              <p>Keep humans in control for sensitive actions while routine work keeps moving.</p>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
