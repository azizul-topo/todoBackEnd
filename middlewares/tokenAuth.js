const jwt = require("jsonwebtoken");

const tokenAuth = (req, res, next) => {
  try {
    // Check if we're in a development environment and allow mock data
    if (process.env.NODE_ENV === "development" || process.env.MOCK_USER === "true") {
      req.user = { id: req.body.id }; // Mock user for testing
      return next();
    }

    // Extract the token from the Authorization header
    const token = req.header("Authorization")?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "Access denied. No token provided.", success: false });
    }

    // Retrieve the secret key from the environment variables
    const secretKey = process.env.AUTH_SECRET_KEY;
    if (!secretKey) {
      throw new Error("Secret key for authentication is not defined in the environment variables.");
    }

    // Verify the token and decode the user information
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded; // Attach the user info to the request object
    next();
  } catch (error) {
    console.error("Error verifying token:", error.message);
    res.status(401).json({ message: "Invalid token.", success: false });
  }
};

module.exports = tokenAuth;
