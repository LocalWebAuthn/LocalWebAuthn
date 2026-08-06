import type { BrowserContext, Page } from '@playwright/test';

import { expect, test } from '@playwright/test';

async function addVirtualPasskey(context: BrowserContext, page: Page) {
  const client = await context.newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

test('self-serve signup: channel proofs cooperate, then the claimed link enrolls', async ({
  browser,
  page,
}) => {
  const email = `selfserve-${String(Date.now())}@example.test`;

  await page.goto('http://localhost:4173/');
  await expect(page.getByRole('heading', { name: 'Sign in with a passkey' })).toBeVisible();
  await page.getByLabel('Display name').fill('Self Serve');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel(/Mobile phone/u).fill('+15550009999');
  await page.getByRole('button', { name: 'Start signup' }).click();
  await expect(page.getByRole('heading', { name: 'Simulated messages' })).toBeVisible();

  // Two proof links, both capability-free (no enrollment token exists yet).
  const links = await page
    .locator('.sim-message a')
    .evaluateAll((anchors) => anchors.map((anchor) => (anchor as HTMLAnchorElement).href));
  expect(links).toHaveLength(2);
  for (const link of links) {
    expect(link).toContain('/signup#signup=');
    expect(link).not.toContain('enroll#token');
  }
  const emailLink = links.find((link) => link.includes('channel=email')) ?? '';
  const phoneLink = links.find((link) => link.includes('channel=phone')) ?? '';

  // Channel 1: the email proof page confirms, then waits on the machine.
  const emailPage = await browser.newPage();
  await emailPage.goto(emailLink);
  await emailPage.getByRole('button', { name: 'Confirm this email' }).click();
  await expect(emailPage.getByText(/Still waiting for/u)).toBeVisible();

  // Channel 2: the phone proof page confirms last and completes the machine.
  const phoneContext = await browser.newContext();
  const phonePage = await phoneContext.newPage();
  await addVirtualPasskey(phoneContext, phonePage);
  await phonePage.goto(phoneLink);
  await phonePage.getByRole('button', { name: 'Confirm this phone' }).click();
  await expect(phonePage.getByRole('button', { name: 'Create my passkey here' })).toBeVisible();

  // Cooperating pages: the waiting email page flips to claimable by itself.
  await expect(emailPage.getByRole('button', { name: 'Create my passkey here' })).toBeVisible({
    timeout: 10_000,
  });

  // Enroll on the preferred device (the phone page).
  await phonePage.getByRole('button', { name: 'Create my passkey here' }).click();
  await expect(
    phonePage.getByRole('button', { name: 'Create passkey', exact: true }),
  ).toBeVisible();
  await phonePage.getByRole('button', { name: 'Create passkey', exact: true }).click();
  await expect(phonePage.getByRole('heading', { name: 'Your access' })).toBeVisible();

  // The enrollment is single-use: the other page's claim fails loudly.
  await emailPage.getByRole('button', { name: 'Create my passkey here' }).click();
  await expect(emailPage.getByText(/already used/u)).toBeVisible();
  await emailPage.close();

  // --- Recovery is not signup -----------------------------------------------
  // Re-running the flow for the now-existing account opens a waiting period
  // after both proofs, and a passkey sign-in (the Signal-style activity veto)
  // cancels it — the owner is present, so nobody needs re-enrollment.
  await page.reload();
  await page.getByLabel('Display name').fill('Whoever Initiated');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel(/Mobile phone/u).fill('+15550009999');
  await page.getByRole('button', { name: 'Start signup' }).click();
  await expect(
    page.getByRole('heading', { name: 'Simulated messages (account recovery)' }),
  ).toBeVisible();
  const recoveryLinks = await page
    .locator('.sim-message a')
    .evaluateAll((anchors) => anchors.map((anchor) => (anchor as HTMLAnchorElement).href));
  for (const link of recoveryLinks) {
    expect(link).toContain('intent=recovery');
  }

  // Confirm both channels; the machine completes into the waiting period.
  const proofPage = await browser.newPage();
  await proofPage.goto(recoveryLinks.find((link) => link.includes('channel=email')) ?? '');
  await expect(proofPage.getByText(/replace this account/u)).toBeVisible();
  await proofPage.getByRole('button', { name: 'I started this' }).click();
  const proofPage2 = await browser.newPage();
  await proofPage2.goto(recoveryLinks.find((link) => link.includes('channel=phone')) ?? '');
  await proofPage2.getByRole('button', { name: 'I started this' }).click();
  await expect(proofPage2.getByText(/re-enrollment waits/u)).toBeVisible();

  // Existing passkeys keep working during the window — and signing in with
  // one vetoes the recovery. The waiting proof pages flip to canceled.
  await phonePage.getByRole('button', { name: 'Sign out', exact: true }).click();
  await phonePage.getByRole('button', { name: 'Continue with passkey' }).click();
  await expect(phonePage.getByRole('heading', { name: 'Your access' })).toBeVisible();
  await expect(proofPage2.getByText(/canceled/u)).toBeVisible({ timeout: 10_000 });
  await expect(proofPage2.getByText(/account is unchanged/u)).toBeVisible();

  await proofPage.close();
  await proofPage2.close();
  await phoneContext.close();
});
