import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Elmora — Managed AI workers for operations",
  description:
    "Elmora provides managed AI workers for inbox, booking, and back-office operations.",
  metadataBase: new URL("https://elmora-kappa.vercel.app"),
  openGraph: {
    title: "Elmora — Managed AI workers for operations",
    description:
      "Managed AI workers for inbox, booking, and back-office operations.",
    url: "https://elmora-kappa.vercel.app",
    siteName: "Elmora",
    type: "website",
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <header className="site-header">
          <div className="container nav">
            <Link className="logo" href="/" aria-label="Elmora home">
              <span className="logo-mark">E</span>
              <span>Elmora</span>
            </Link>
            <nav className="nav-links" aria-label="Main navigation">
              <Link href="/#workers">Workers</Link>
              <Link href="/privacy">Privacy</Link>
              <Link href="/terms">Terms</Link>
              <Link className="button" href="/connect/google">Connect Google</Link>
            </nav>
          </div>
        </header>
        {children}
        <footer className="site-footer">
          <div className="container footer-inner">
            <span>© {new Date().getFullYear()} Elmora. All rights reserved.</span>
            <div className="footer-links">
              <Link href="/privacy">Privacy</Link>
              <Link href="/terms">Terms</Link>
              <Link href="/connect/google">Google OAuth</Link>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
