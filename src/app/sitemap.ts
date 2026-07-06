import type { MetadataRoute } from 'next';

const baseUrl = process.env.NEXT_PUBLIC_SITE_URL || 'https://elmora-kappa.vercel.app';

export default function sitemap(): MetadataRoute.Sitemap {
  return ['', '/privacy', '/terms', '/connect/google', '/oauth/google/callback'].map((path) => ({
    url: `${baseUrl}${path}`,
    lastModified: new Date(),
  }));
}
