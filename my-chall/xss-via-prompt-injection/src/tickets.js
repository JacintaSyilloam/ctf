const express = require('express');
const { requireAuth } = require('./auth');
const { getAllUsers, createTicket, getTicketById, getTicketsAssignedTo, getTicketsCreatedBy } = require('./db');
const { summarizeTicket } = require('./ai');
const { visitTicket } = require('./bot');

const router = express.Router();

// Dashboard page
router.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile('dashboard.html', { root: './public' });
});

// Get all users for assignment dropdown
router.get('/api/users', requireAuth, (req, res) => {
  const users = getAllUsers();
  // Filter out current user
  const otherUsers = users.filter(u => u.username !== req.user.username);
  res.json(otherUsers);
});

// Get tickets assigned to current user
router.get('/api/tickets/assigned', requireAuth, (req, res) => {
  const tickets = getTicketsAssignedTo(req.user.username);
  res.json(tickets);
});

// Get tickets created by current user
router.get('/api/tickets/created', requireAuth, (req, res) => {
  const tickets = getTicketsCreatedBy(req.user.username);
  res.json(tickets);
});

// Create new ticket
router.post('/api/tickets', requireAuth, express.json(), async (req, res) => {
  const { title, description, assignedTo } = req.body;
  
  if (!title || !description || !assignedTo) {
    return res.status(400).json({ error: 'Title, description, and assignedTo are required' });
  }
  
  // Prevent self-assignment
  if (assignedTo === req.user.username) {
    return res.status(400).json({ error: 'Cannot assign ticket to yourself' });
  }
  
  let summary = null;
  
  // Summarize if description is longer than 500 characters
  if (description.length > 500) {
    console.log('[Ticket] Description exceeds 500 chars, generating AI summary...');
    summary = await summarizeTicket(description);
    console.log('[Ticket] Summary generated:', summary.substring(0, 100) + '...');
  }
  
  const ticketId = createTicket(
    title,
    description,
    summary,
    req.user.username,
    assignedTo
  );
  
  console.log(`[Ticket] Created ticket ${ticketId} from ${req.user.username} to ${assignedTo}`);
  
  // If ticket has summary and is assigned to admin, trigger bot visit
  if (summary && assignedTo === 'admin') {
    console.log('[Ticket] Triggering admin bot to visit ticket...');
    // Don't await - let it run in background
    visitTicket(ticketId).catch(err => {
      console.error('[Bot] Error visiting ticket:', err.message);
    });
  }
  
  res.json({ success: true, ticketId });
});

// View specific ticket
router.get('/dashboard/tickets/:id', requireAuth, (req, res) => {
  res.sendFile('ticket.html', { root: './public' });
});

// Get ticket details API
router.get('/api/tickets/:id', requireAuth, (req, res) => {
  const ticket = getTicketById(req.params.id);
  
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket not found' });
  }
  
  // Only allow access if user is assigned to or created the ticket
  if (ticket.assigned_to !== req.user.username && ticket.assigned_from !== req.user.username) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  res.json(ticket);
});

module.exports = router;
