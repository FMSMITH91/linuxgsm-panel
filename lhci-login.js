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
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'load', timeout: 20000 }).catch(() => {}),
      page.click('button[type="submit"]'),
    ]);
  } finally {
    await page.close();
  }
};
