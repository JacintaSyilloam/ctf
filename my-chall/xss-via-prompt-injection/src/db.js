const Database = require('better-sqlite3');
const crypto = require('crypto');

// Create in-memory SQLite database
const db = new Database(':memory:');

// Static admin cookie for the CTF
const ADMIN_COOKIE = 'admin_' + crypto.randomBytes(32).toString('hex');

// Initialize database schema
function initDatabase() {
  // Create users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      cookie TEXT UNIQUE NOT NULL,
      is_admin INTEGER DEFAULT 0
    )
  `);

  // Create tickets table
  db.exec(`
    CREATE TABLE IF NOT EXISTS tickets (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      summary TEXT,
      assigned_from TEXT NOT NULL,
      assigned_to TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (assigned_from) REFERENCES users(username),
      FOREIGN KEY (assigned_to) REFERENCES users(username)
    )
  `);

  // Insert dummy users
  const insertUser = db.prepare('INSERT INTO users (username, password, cookie, is_admin) VALUES (?, ?, ?, ?)');
  
  // Admin user (static cookie)
  insertUser.run('admin', 'admin_' + crypto.randomBytes(16).toString('hex'), ADMIN_COOKIE, 1);
  
  // Test user
  insertUser.run('test', 'test123', 'test_' + crypto.randomBytes(32).toString('hex'), 0);
  
  // Dummy users with random credentials
  const dummyUsers = [
    { username: 'john_smith', password: crypto.randomBytes(12).toString('hex') },
    { username: 'sarah_jones', password: crypto.randomBytes(12).toString('hex') },
    { username: 'mike_wilson', password: crypto.randomBytes(12).toString('hex') },
    { username: 'emma_brown', password: crypto.randomBytes(12).toString('hex') }
  ];

  for (const user of dummyUsers) {
    const userCookie = user.username + '_' + crypto.randomBytes(32).toString('hex');
    insertUser.run(user.username, user.password, userCookie, 0);
  }

  console.log('[DB] Database initialized successfully');
  console.log('[DB] Test user credentials: test / test123');
  console.log('[DB] Admin cookie:', ADMIN_COOKIE);
}

// User operations
function getUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function getUserByCookie(cookie) {
  return db.prepare('SELECT * FROM users WHERE cookie = ?').get(cookie);
}

function getAllUsers() {
  return db.prepare('SELECT username FROM users ORDER BY username').all();
}

function verifyCredentials(username, password) {
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
  return user || null;
}

// Ticket operations
function createTicket(title, description, summary, assignedFrom, assignedTo) {
  const id = crypto.randomBytes(16).toString('hex');
  const createdAt = Date.now();
  
  db.prepare(`
    INSERT INTO tickets (id, title, description, summary, assigned_from, assigned_to, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, title, description, summary, assignedFrom, assignedTo, createdAt);
  
  return id;
}

function getTicketById(id) {
  return db.prepare('SELECT * FROM tickets WHERE id = ?').get(id);
}

function getTicketsAssignedTo(username) {
  return db.prepare(`
    SELECT * FROM tickets 
    WHERE assigned_to = ? 
    ORDER BY created_at DESC
  `).all(username);
}

function getTicketsCreatedBy(username) {
  return db.prepare(`
    SELECT * FROM tickets 
    WHERE assigned_from = ? 
    ORDER BY created_at DESC
  `).all(username);
}

// Initialize on module load
initDatabase();

module.exports = {
  db,
  ADMIN_COOKIE,
  getUserByUsername,
  getUserByCookie,
  getAllUsers,
  verifyCredentials,
  createTicket,
  getTicketById,
  getTicketsAssignedTo,
  getTicketsCreatedBy
};
