import type { BrowserContext, Page } from '@playwright/test';

import { expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

import { createDemoApplication, ensureBootstrapAdministrator } from '../src/application';
import { openDemoDatabase } from '../src/database';

async function addVirtualPasskey(context: BrowserContext, page: Page) {
  const client = await context.newCDPSession(page);
  await client.send('WebAuthn.enable');
  const authenticator = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { client, authenticatorId: authenticator.authenticatorId };
}

async function administratorEnrollmentUrl(): Promise<string> {
  const database = openDemoDatabase('examples/demo/.data/e2e.db');
  const { authentication } = createDemoApplication(database, {
    auth: {
      publicOrigin: 'http://localhost:4173',
      rpId: 'localhost',
      rpName: 'LocalWebAuthn Demo',
    },
  });
  const enrollment = await ensureBootstrapAdministrator(database, authentication, {
    email: 'admin@example.test',
    displayName: 'Demo Administrator',
  });
  database.close();
  if (!enrollment) {
    throw new Error('The administrator is already enrolled.');
  }
  return enrollment.enrollmentUrl;
}

async function capture(page: Page, name: string): Promise<void> {
  const screenshotDirectory = process.env.DEMO_SCREENSHOT_DIR;
  if (!screenshotDirectory) {
    return;
  }
  const directory = resolve(screenshotDirectory);
  mkdirSync(directory, { recursive: true });
  await page.screenshot({
    path: resolve(directory, name),
    fullPage: true,
  });
}

test('runs the bootstrap, client enrollment, and additional-passkey lifecycle', async ({
  browser,
  page,
}) => {
  await addVirtualPasskey(page.context(), page);
  await page.goto(await administratorEnrollmentUrl());
  await expect(page.getByRole('heading', { name: 'Create your passkey' })).toBeVisible();
  await expect(page.getByText('Demo Administrator')).toBeVisible();
  await capture(page, 'demo-enrollment.png');
  await page.getByRole('button', { name: 'Create passkey' }).click();
  await expect(page.getByRole('heading', { name: 'Manage access' })).toBeVisible();

  await page.getByRole('button', { name: 'Add person' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add person' });
  await dialog.getByLabel('Display name').fill('Ada Client');
  await dialog.getByLabel(/Email/u).fill('ada@example.test');
  await dialog.getByRole('button', { name: 'Create and issue link' }).click();

  const enrollmentUrl = await page.getByRole('textbox', { name: 'Enrollment URL' }).inputValue();
  expect(enrollmentUrl).toMatch(/^http:\/\/localhost:4173\/enroll#token=[a-z2-7]{52}$/u);
  const row = page.getByRole('row').filter({ hasText: 'ada@example.test' });
  await expect(row.getByText('Pending')).toBeVisible();
  await page.getByRole('button', { name: 'Dismiss enrollment URL' }).click();

  const clientContext = await browser.newContext();
  const clientPage = await clientContext.newPage();
  const firstPasskey = await addVirtualPasskey(clientContext, clientPage);
  await clientPage.goto(enrollmentUrl);
  await expect(clientPage.getByRole('heading', { name: 'Create your passkey' })).toBeVisible();
  await expect(clientPage.getByText('Ada Client')).toBeVisible();
  await clientPage.getByRole('button', { name: 'Create passkey' }).click();
  await expect(clientPage.getByRole('heading', { name: 'Your access' })).toBeVisible();
  await expect(clientPage.locator('.passkey-item')).toHaveCount(1);

  await firstPasskey.client.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: firstPasskey.authenticatorId,
  });
  await addVirtualPasskey(clientContext, clientPage);
  await clientPage.getByRole('button', { name: 'Add passkey' }).click();
  await expect(clientPage.getByText('Additional passkey registered.')).toBeVisible();
  await expect(clientPage.locator('.passkey-item')).toHaveCount(2);
  await clientPage.setViewportSize({ width: 390, height: 844 });
  await capture(clientPage, 'demo-passkeys-mobile.png');

  await clientPage.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(clientPage.getByRole('heading', { name: 'Sign in with a passkey' })).toBeVisible();
  await clientPage.getByRole('button', { name: 'Continue with passkey' }).click();
  await expect(clientPage.getByRole('heading', { name: 'Your access' })).toBeVisible();

  await expect(clientPage.getByRole('button', { name: 'Add passkey' })).toBeVisible();
  expect(
    await clientPage.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBe(true);

  // Self-service sessions-only control. Registering the additional passkey
  // opened a fresh session and left the previous one live server-side; this
  // ends that one while the current session is excepted and stays signed in.
  await clientPage.getByRole('button', { name: 'Sign out other devices' }).click();
  await expect(
    clientPage.getByText('Signed out 1 other session. Your passkeys are unchanged.'),
  ).toBeVisible();
  await expect(clientPage.getByRole('heading', { name: 'Your access' })).toBeVisible();

  // Admin list was loaded before Ada enrolled; reload session to see passkey counts.
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Manage access' })).toBeVisible();
  const adaRow = page.getByRole('row').filter({ hasText: 'ada@example.test' });
  await expect(adaRow.getByText('Enrolled')).toBeVisible();
  await capture(page, 'demo-administration.png');

  // Sessions-only response first: end Ada's sessions everywhere. Her passkeys
  // survive and she signs straight back in with the same one — contrast with
  // the credential-destroying Re-enroll below.
  await adaRow.getByRole('button', { name: 'Sign out Ada Client everywhere' }).click();
  await expect(page.getByText(/Ended 1 session for Ada Client/u)).toBeVisible();
  await expect(adaRow.getByText('Enrolled')).toBeVisible();

  await clientPage.reload();
  await expect(clientPage.getByRole('heading', { name: 'Sign in with a passkey' })).toBeVisible();
  await clientPage.getByRole('button', { name: 'Continue with passkey' }).click();
  await expect(clientPage.getByRole('heading', { name: 'Your access' })).toBeVisible();

  // Recovery: revoke-then-issue (documented order) as a single admin action.
  page.once('dialog', (dialog) => dialog.accept());
  await adaRow.getByRole('button', { name: 'Re-enroll' }).click();
  await expect(page.getByText('Passkeys revoked and recovery enrollment issued.')).toBeVisible();
  const recoveryUrl = await page.getByRole('textbox', { name: 'Enrollment URL' }).inputValue();
  expect(recoveryUrl).toMatch(/^http:\/\/localhost:4173\/enroll#token=[a-z2-7]{52}$/u);
  expect(recoveryUrl).not.toBe(enrollmentUrl);
  await expect(adaRow.getByText('Pending')).toBeVisible();

  await clientContext.close();
});
