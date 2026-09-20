import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  workers: 1,
  use: {
    baseURL: process.env.RANGER_UI_URL || 'http://127.0.0.1:5173',
    channel: process.env.PLAYWRIGHT_CHANNEL || 'msedge',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
})
