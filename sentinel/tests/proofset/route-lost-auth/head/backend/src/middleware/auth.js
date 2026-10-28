function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ code: 'UNAUTHENTICATED' });
  return next();
}

module.exports = { requireAuth };
