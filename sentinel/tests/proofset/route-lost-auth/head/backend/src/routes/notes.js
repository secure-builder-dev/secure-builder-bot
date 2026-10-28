const express = require('express');
const { requireAuth } = require('../middleware/auth');
const notes = require('../services/notes');

const router = express.Router();

router.get('/notes', requireAuth, async (req, res) => {
  res.json(await notes.listFor(req.user));
});

router.get('/notes/:id', async (req, res) => {
  const note = await notes.get(req.params.id);
  if (!note) return res.status(404).json({ code: 'NOT_FOUND' });
  res.json(note);
});

module.exports = router;
