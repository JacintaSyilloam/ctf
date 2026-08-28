const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const { router: authRouter, requireAuth } = require('./auth');
const ticketsRouter = require('./tickets');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Custom static file middleware to block .js files
app.use(express.static('public', {
  setHeaders: (res, filePath) => {
    // Block direct access to .js files
    if (filePath.endsWith('.js')) {
      res.status(403).send('Forbidden');
      return;
    }
  }
}));

// Override the static middleware for .js files specifically
app.use('*.js', (req, res) => {
  res.status(403).send('Forbidden');
});

// Security headers (but not too secure for CTF purposes)
app.use((req, res, next) => {
  // Allow XSS for the challenge - no CSP
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// Routes
app.use('/', authRouter);
app.use('/', ticketsRouter);

// Root redirect
app.get('/', (req, res) => {
  if (req.cookies.session) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// Flag endpoint - admin only
app.get('/api/flag', requireAuth, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  res.json({ 
    flag: 'FLAG{another_baby_xss_via_prompt_injection}'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).send('404 - Not Found');
});

// Error handler
app.use((err, req, res, next) => {
  console.error('[Error]', err);
  res.status(500).send('Internal Server Error');
});

// Start server
app.listen(PORT, () => {
  console.log(`[Server] ManagementPro running on http://localhost:${PORT}`);
  console.log(`[Server] Login at http://localhost:${PORT}/login`);
});
