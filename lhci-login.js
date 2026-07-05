// Lighthouse CI auth setup: log the throwaway panel in so authenticated pages can
// be audited. Runs once before collection; disableStorageReset keeps the session.
// Waits on 'load' (not networkidle — the app opens a persistent socket that never
// goes idle) and explicitly waits for the form field so the login can't race.
module.exports = async (browser) => {
  const page = await browser.newPage();
  await page.goto('http://127.0.0.1:5000/login', { waitUntil: 'load' });
  await page.waitForSelector('#username', { timeout: 20000 });
  await page.type('#username', 'lhci');
  await page.type('#password', 'Str0ng!passw0rd-lhci');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'load', timeout: 20000 }).catch(() => {}),
    page.click('button[type="submit"]'),
  ]);
  await page.close();
};
