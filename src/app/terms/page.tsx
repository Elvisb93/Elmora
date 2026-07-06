export const metadata = {
  title: "Terms of Service — Elmora",
  description: "Elmora terms of service for the website and managed AI worker preview.",
};

export default function TermsPage() {
  return (
    <main className="container doc-page">
      <article className="doc-card">
        <h1>Terms of Service</h1>
        <p><strong>Effective date:</strong> July 6, 2026</p>
        <p>
          These terms apply to the Elmora website and early managed AI worker preview. By using Elmora,
          you agree to use the service responsibly and only for workflows you are authorized to operate.
        </p>

        <h2>Service status</h2>
        <p>
          Elmora is an early-stage managed AI worker product. Features may change, pause, or be replaced
          as the service is developed.
        </p>

        <h2>Acceptable use</h2>
        <ul>
          <li>Do not connect accounts you do not own or administer.</li>
          <li>Do not use Elmora for unlawful, deceptive, abusive, or high-risk activity.</li>
          <li>Review AI-generated drafts and recommendations before relying on them for important decisions.</li>
        </ul>

        <h2>Third-party services</h2>
        <p>
          Elmora may integrate with Google and other third-party services. Your use of those services is
          also governed by their terms and policies.
        </p>

        <h2>No warranty</h2>
        <p>
          Elmora is provided on an “as is” and “as available” basis during this preview period, without
          warranties of any kind to the fullest extent permitted by law.
        </p>

        <h2>Contact</h2>
        <p>
          For terms or service questions, contact the Elmora operator through the channel provided during onboarding.
        </p>
      </article>
    </main>
  );
}
