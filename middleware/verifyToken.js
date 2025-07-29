const jwt = require('jsonwebtoken');
const SECRET = 'supersecretkey';

function verifyToken(req, res, next) {
  const token = req.headers['x-auth'];

  if (!token) {
    return res.status(403).json({ message: 'Token missing' });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

module.exports = verifyToken;
