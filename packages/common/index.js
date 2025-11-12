const jwt = require('jsonwebtoken');

function getEnv(name, fallback) {
  const v = process.env[name];
  if (!v && typeof fallback === 'undefined') {
    throw new Error(`Missing required env: ${name}`);
  }
  return v || fallback;
}

function verifyAccessToken(token) {
  const publicKey = getEnv('JWT_PUBLIC_KEY', '');
  try {
    return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
  } catch (e) {
    return null;
  }
}

function signAccessToken(payload) {
  const privateKey = getEnv('JWT_PRIVATE_KEY', '');
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '15m' });
}

function signRefreshToken(payload) {
  const privateKey = getEnv('JWT_PRIVATE_KEY', '');
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '7d' });
}

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const claims = verifyAccessToken(token);
  if (!claims) return res.status(401).json({ error: 'Invalid token' });
  req.user = claims;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

module.exports = {
  getEnv,
  verifyAccessToken,
  signAccessToken,
  signRefreshToken,
  requireAuth,
  requireRole
};
