const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) return res.status(401).json({ error: 'Token diperlukan' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token invalid/expired' });
    req.user = decoded.user;
    next();
  });
}
function authorizeRole(requiredRole){
return (req, res, next) => {
  if(req.user && req.user.role === requiredRole){
    next();
  }else{ return res.status(403).json({error: 'AksesDilarang: Perantidakmemadai'});
  }
};
}
module.exports = {authenticateToken, authorizeRole};