const express = require('express');
const { requireRole } = require('../middleware/roles');
const users = require('../services/users');

const router = express.Router();

router.delete('/users/:id', async (req, res) => {
  await users.deactivate(req.params.id);
  res.status(204).end();
});

module.exports = router;
