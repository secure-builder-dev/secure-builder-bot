function scopeToTenant(query, user) {
  if (!user || !user.tenantId) throw new Error('no tenant');
  return query.where({ tenant_id: user.tenantId });
}

module.exports = { scopeToTenant };
