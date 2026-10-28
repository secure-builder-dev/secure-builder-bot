const db = require('../db');
const { scopeToTenant } = require('../scope/tenant');

async function listInvoices(user) {
  return scopeToTenant(db('invoices'), user).select('*').limit(100);
}

module.exports = { listInvoices };
