import { expect, test } from '@playwright/test'

test('run button starts the real runner and displays its terminal result', async ({ page }) => {
  test.skip(!process.env.RANGER_TEST_MODEL || !process.env.RANGER_TEST_TARGET, 'Set the local fixture model and target before running integration tests')
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  await page.goto('/')
  await page.locator('.scenario-field select').selectOption('JS-S1-001')
  await page.locator('.model-field input').fill(process.env.RANGER_TEST_MODEL || 'deepseek-flash')
  await page.locator('.target-field input').fill(process.env.RANGER_TEST_TARGET || 'http://127.0.0.1:3001')
  await page.getByLabel('Reset target before each run').uncheck()
  await page.getByRole('button', { name: 'Advanced +' }).click()
  await page.getByLabel('MAX STEPS', { exact: true }).fill('1')
  const started = page.waitForResponse(response => response.url().endsWith('/api/runs/batch') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Start live run', exact: true }).click()
  const response = await started
  expect(response.status()).toBe(202)
  const { job_id } = await response.json()
  const batchUrl = `/api/runs/batch/${job_id}`
  await expect.poll(async () => (await (await page.request.get(batchUrl)).json()).completed, { timeout: 30000 }).toBe(1)
  const batch = await (await page.request.get(batchUrl)).json()
  console.log(JSON.stringify(batch))
  await page.screenshot({ path: 'test-results/run-result.png', fullPage: true })
  expect(errors).toEqual([])
  expect(batch.runs[0].error).toBeFalsy()
  expect(batch.runs[0].state).not.toBe('invalid')
})
