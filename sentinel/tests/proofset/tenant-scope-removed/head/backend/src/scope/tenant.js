function scopeToTenant(query, user) {
  if (!user) throw new Error('no user');
  return query;
}

module.exports = { scopeToTenant };
