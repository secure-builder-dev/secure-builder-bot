function requireRole(role) {
  return (req, res, next) => (req.user && req.user.role === role ? next() : res.status(403).json({ code: 'FORBIDDEN' }));
}

module.exports = { requireRole };
