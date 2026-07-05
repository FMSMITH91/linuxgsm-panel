// Lighthouse CI auth setup: log the throwaway panel in so authenticated pages
// (the dashboard) can be audited. Runs once before collection; disableStorageReset
// in the config keeps the session cookie for the audited URLs.
module.exports = async (browser) => {
  const page = await browser.newPage();
  await page.goto('http://127.0.0.1:5000/login', { waitUntil: 'networkidle0' });
  await page.type('#username', 'lhci');
  await page.type('#password', 'Str0ng!passw0rd-lhci');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle0' }),
    page.click('button[type="submit"]'),
  ]);
  await page.close();
};
