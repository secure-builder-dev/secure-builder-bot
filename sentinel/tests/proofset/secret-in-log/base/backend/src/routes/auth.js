const express = require('express');
const logger = require('../logger');
const users = require('../services/users');

const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await users.verify(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ code: 'BAD_CREDENTIALS' });
  logger.info('login', { userId: user.id });
  res.json({ token: user.token });
});

module.exports = router;
