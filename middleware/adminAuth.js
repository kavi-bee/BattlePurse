const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  try {
    const authHeader = req.header("Authorization");

    if (!authHeader)
      return res.status(401).json({ msg: "No token provided, access denied" });

    // ✅ Handle both "Bearer <token>" and "<token>" formats safely
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1].trim()
      : authHeader.trim();

    if (!token)
      return res.status(401).json({ msg: "Invalid token format" });

    // ✅ Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded.isAdmin)
      return res.status(403).json({ msg: "Forbidden: Admins only" });

    req.user = decoded;
    next();
  } catch (err) {
    console.error("Admin auth error:", err.message);
    res.status(401).json({ msg: "Invalid or expired token" });
  }
};
