// Lighthouse CI auth setup. LHCI calls this once PER URL, and disableStorageReset
// keeps the session cookie — so on the 2nd+ page we're already logged in and /login
// redirects to /. Detect that and skip, otherwise the login races on a missing field.
module.exports = async (browser) => {
  const page = await browser.newPage();
  try {
    await page.goto('http://127.0.0.1:5000/login', { waitUntil: 'load' });
    // Already authenticated? /login redirects away, or the field is absent.
    if (!page.url().includes('/login') || !(await page.$('#username'))) return;
    await page.type('#username', 'lhci');
    await page.type('#password', 'Str0ng!passw0rd-lhci');
    // No .catch() on the navigation, and the result is CHECKED. Swallowing it meant a login that
    // never completed — a renamed field, a changed password, a slow boot — left LHCI
    // unauthenticated, every URL landed on /login, and the CLS/a11y assertions passed on a login
    // form. Throwing here fails the collect step, which is the honest outcome.
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'load', timeout: 20000 }),
      page.click('button[type="submit"]'),
    ]);
    if (page.url().includes('/login')) {
      throw new Error('lhci-login: still on /login after submitting — every page would be '
                      + 'audited as the login form. Check the credentials in tools/lhci_serve.py.');
    }
  } finally {
    await page.close();
  }
};
