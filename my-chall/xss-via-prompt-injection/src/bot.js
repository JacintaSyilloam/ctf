const puppeteer = require('puppeteer');
const { ADMIN_COOKIE } = require('./db');

let browser = null;

async function initBrowser() {
  if (!browser) {
    browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--disable-gpu',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process'
      ]
    });
    console.log('[Bot] Browser initialized');
  }
  return browser;
}

async function visitTicket(ticketId) {
  try {
    console.log(`[Bot] Admin bot visiting ticket ${ticketId}...`);
    
    const browser = await initBrowser();
    const page = await browser.newPage();
    
    // Set admin cookie
    await page.setCookie({
      name: 'session',
      value: ADMIN_COOKIE,
      domain: 'localhost',
      path: '/',
      httpOnly: false
    });
    
    // Visit the ticket page
    const url = `http://localhost:3000/dashboard/tickets/${ticketId}`;
    console.log(`[Bot] Navigating to ${url}`);
    
    await page.goto(url, { 
      waitUntil: 'networkidle2',
      timeout: 10000 
    });
    
    // Wait a bit to let any XSS execute
    await page.waitForTimeout(3000);
    
    console.log(`[Bot] Admin bot finished visiting ticket ${ticketId}`);
    
    await page.close();
  } catch (error) {
    console.error(`[Bot] Error visiting ticket ${ticketId}:`, error.message);
    throw error;
  }
}

// Cleanup on exit
process.on('exit', async () => {
  if (browser) {
    await browser.close();
  }
});

module.exports = {
  visitTicket
};
