// @ts-check
import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
  site: 'https://xsend.com',
  integrations: [tailwind(), sitemap()],
  i18n: {
    defaultLocale: 'en',
    locales: [
      'en', 'zh', 'es', 'hi', 'ar',
      'pt', 'bn', 'ru', 'ja', 'de',
      'fr', 'ko', 'tr', 'it', 'vi',
      'pl', 'nl', 'id', 'th', 'fil'
    ],
    routing: {
      prefixDefaultLocale: false,
      strategy: 'pathname',
    },
    fallback: {
      'zh': 'en', 'es': 'en', 'hi': 'en', 'ar': 'en',
      'pt': 'en', 'bn': 'en', 'ru': 'en', 'ja': 'en',
      'de': 'en', 'fr': 'en', 'ko': 'en', 'tr': 'en',
      'it': 'en', 'vi': 'en', 'pl': 'en', 'nl': 'en',
      'id': 'en', 'th': 'en', 'fil': 'en',
    }
  }
});