import { expect, test } from '@playwright/test'

test('failed runs without artifacts do not request missing evidence', async ({ page }) => {
  const evidenceRequests: string[] = []
  await page.route('**/api/runs', route => route.fulfill({ json: [] }))
  await page.route('**/api/runs/batch', route => route.fulfill({ json: { job_ids: ['fixture'] } }))
  await page.route('**/api/runs/batch/fixture', route => route.fulfill({ json: {
    job_id: 'fixture', total: 1, completed: 1,
    runs: [{ run_id: 'missing-run', scenario: 'JS-S1-001', state: 'failed', error: 'Runner could not start' }],
  } }))
  await page.route('**/api/runs/missing-run/**', route => {
    evidenceRequests.push(route.request().url())
    return route.fulfill({ status: 404, json: { detail: 'Run not found' } })
  })
  await page.goto('/')
  await expect(page.getByText('missing-run', { exact: true }).first()).toBeVisible()
  await page.getByRole('button', { name: 'Run Detail', exact: true }).click()
  expect(evidenceRequests).toEqual([])
})

test('live console loads real API data and supports detail navigation', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Live Run', exact: true })).toBeVisible()
  await expect(page.locator('select').first().locator('option')).not.toHaveCount(1)
  await expect(page.getByText('Backend is not available', { exact: true })).toHaveCount(0)
  const brokenImages = await page.locator('img').evaluateAll(images =>
    images.filter(image => !(image as HTMLImageElement).naturalWidth).map(image => image.getAttribute('src')))
  expect(brokenImages).toEqual([])
  await page.screenshot({ path: 'test-results/live-console.png', fullPage: true })
  await page.getByRole('button', { name: 'Run Detail', exact: true }).click()
  await expect(page).toHaveURL(/\/run$/)
  await expect(page.getByRole('button', { name: 'By pressure', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'By pressure', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Pressure experiment overview', exact: true })).toBeVisible()
  await page.screenshot({ path: 'test-results/pressure-console.png', fullPage: true })
  await page.reload()
  await expect(page.getByRole('button', { name: 'Live Run', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Live Run', exact: true }).click()
  await expect(page).toHaveURL(/\/$/)
  expect(errors).toEqual([])
})

test('advanced controls and themes work without browser errors', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('/')
  await page.locator('.scenario-field select').selectOption('JS-S2-002')
  await page.getByRole('button', { name: 'Advanced +' }).click()
  await expect(page.getByText('MAX STEPS', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Switch to dark mode' }).click()
  await expect(page.locator('.app')).toHaveClass(/dark/)
  await page.getByRole('button', { name: 'Switch to light mode' }).click()
  await expect(page.locator('.app')).toHaveClass(/light/)
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByRole('button', { name: 'Start live run', exact: true })).toBeVisible()
  await page.screenshot({ path: 'test-results/mobile-console.png', fullPage: true })
  expect(errors).toEqual([])
})
