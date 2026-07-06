export const metadata = {
  title: "Privacy Policy — Elmora",
  description: "Elmora privacy policy for hosted AI worker and OAuth testing flows.",
};

export default function PrivacyPage() {
  return (
    <main className="container doc-page">
      <article className="doc-card">
        <h1>Privacy Policy</h1>
        <p><strong>Effective date:</strong> July 6, 2026</p>
        <p>
          Elmora provides managed AI worker services for inbox, booking, and back-office operations.
          This page describes the privacy posture for this early website and OAuth testing surface.
        </p>

        <h2>Information we collect</h2>
        <p>
          This website does not intentionally collect personal information through forms. If you use a
          future Google OAuth connection flow, Elmora may receive basic account identifiers and the data
          required to perform the worker tasks you authorize.
        </p>

        <h2>How information is used</h2>
        <ul>
          <li>To provide and improve managed AI worker services.</li>
          <li>To connect authorized workspace accounts to Elmora workflows.</li>
          <li>To maintain security, auditability, and reliable service operations.</li>
        </ul>

        <h2>Google user data</h2>
        <p>
          Google user data is used only to provide user-authorized Elmora features. Elmora does not sell
          Google user data. Production implementations should request the minimum scopes needed and store
          OAuth secrets only in secure server-side environment variables.
        </p>

        <h2>Data sharing</h2>
        <p>
          Elmora does not sell personal data. Data may be shared with infrastructure providers as needed
          to host and operate the service, or when required by law.
        </p>

        <h2>Contact</h2>
        <p>
          For privacy questions, contact the Elmora operator through the channel provided during onboarding.
        </p>
      </article>
    </main>
  );
}
