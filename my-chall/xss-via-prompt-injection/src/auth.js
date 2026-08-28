const express = require('express');
const { verifyCredentials, getUserByCookie } = require('./db');

const router = express.Router();

// Authentication middleware
function requireAuth(req, res, next) {
  const sessionCookie = req.cookies.session;
  
  if (!sessionCookie) {
    return res.redirect('/login');
  }
  
  const user = getUserByCookie(sessionCookie);
  
  if (!user) {
    res.clearCookie('session');
    return res.redirect('/login');
  }
  
  req.user = user;
  next();
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Login page
router.get('/login', (req, res) => {
  if (req.cookies.session) {
    const user = getUserByCookie(req.cookies.session);
    if (user) {
      return res.redirect('/dashboard');
    }
  }
  res.sendFile('login.html', { root: './public' });
});

// Login POST
router.post('/login', express.json(), (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const user = verifyCredentials(username, password);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Set session cookie
  res.cookie('session', user.cookie, {
    httpOnly: false, // Allow JavaScript access for XSS challenge
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });
  
  res.json({ success: true, redirect: '/dashboard' });
});

// Logout
router.post('/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ success: true, redirect: '/login' });
});

// Check authentication status
router.get('/api/me', requireAuth, (req, res) => {
  res.json({
    username: req.user.username,
    is_admin: req.user.is_admin
  });
});

module.exports = {
  router,
  requireAuth,
  requireAdmin
};
