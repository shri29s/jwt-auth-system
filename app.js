const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

// Basic middleware
app.use(express.json());

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || "shri-charan-secret";
const MONGODB_URI = process.env.MONGODB_URI;
const SECRET_KEY = "HIDDEN_TREASURE_2025_AUTHENTICATED_ACCESS";

// MongoDB Connection
mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("📦 Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  lastLogin: {
    type: Date,
    default: null,
  },
});

const User = mongoose.model("User", userSchema);

// Helper functions
const generateAccessToken = (user) => {
  return jwt.sign(
    {
      userId: user._id,
      username: user.username,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: "1h" }
  );
};

const hashPassword = async (password) => {
  return await bcrypt.hash(password, 12);
};

const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Middleware for JWT authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "Access denied. No token provided.",
      message: "Please login to access this resource",
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({
          error: "Token expired. Please login again.",
          code: "TOKEN_EXPIRED",
        });
      }
      return res.status(403).json({
        error: "Invalid token.",
      });
    }

    req.user = decoded;
    next();
  });
};

// Middleware for admin-only routes
const requireAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Access denied. Admin privileges required.",
      userRole: req.user.role,
    });
  }
  next();
};

// Routes

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "Authentication Service Online",
    timestamp: new Date().toISOString(),
    database:
      mongoose.connection.readyState === 1 ? "Connected" : "Disconnected",
  });
});

// User Registration
app.post("/register", async (req, res) => {
  try {
    const { username, password, email, role = "user" } = req.body;

    // Basic validation
    if (!username || !password || !email) {
      return res.status(400).json({
        error:
          "Missing required fields: username, password, and email are required",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters long",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
    });

    if (existingUser) {
      return res.status(409).json({
        error: "User already exists with this username or email",
      });
    }

    // Hash password and create user
    const hashedPassword = await hashPassword(password);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role: role === "admin" ? "admin" : "user",
    });

    await newUser.save();

    // Generate token
    const token = generateAccessToken(newUser);

    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        createdAt: newUser.createdAt,
      },
      token,
    });
  } catch (error) {
    if (error.code === 11000) {
      return res
        .status(409)
        .json({ error: "Username or email already exists" });
    }
    console.error("Registration error:", error);
    res
      .status(500)
      .json({ error: "Internal server error during registration" });
  }
});

// User Login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required",
      });
    }

    // Find user by username or email
    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });

    if (!user) {
      return res.status(401).json({
        error: "Invalid credentials",
      });
    }

    // Verify password
    const isValidPassword = await comparePassword(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        error: "Invalid credentials",
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateAccessToken(user);

    res.json({
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        lastLogin: user.lastLogin,
      },
      token,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error during login" });
  }
});

// Protected route - User profile
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      message: "Profile retrieved successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
      },
    });
  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Protected route - Verify token
app.get("/verify", authenticateToken, (req, res) => {
  res.json({
    message: "Token is valid",
    user: {
      userId: req.user.userId,
      username: req.user.username,
      role: req.user.role,
    },
    tokenInfo: {
      isValid: true,
      expiresIn: req.user.exp ? new Date(req.user.exp * 1000) : null,
    },
  });
});

// Admin-only route - Get all users
app.get("/admin/users", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}).select("-password");

    res.json({
      message: "Users retrieved successfully",
      count: users.length,
      users: users.map((user) => ({
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
      })),
    });
  } catch (error) {
    console.error("Admin users error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Secret endpoint - Requires admin access
app.get("/secret", authenticateToken, requireAdmin, (req, res) => {
  res.json({
    message: "Secret Access Granted!",
    secretKey: SECRET_KEY,
    user: req.user.username,
    accessedAt: new Date().toISOString(),
    note: "This secret is only accessible to authenticated admin users",
  });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    availableEndpoints: [
      "POST /register - User registration",
      "POST /login - User login",
      "GET /profile - Get user profile (auth required)",
      "GET /verify - Verify token (auth required)",
      "GET /admin/users - Get all users (admin required)",
      "GET /secret - Access secret key (admin required)",
      "GET /health - Service health check",
    ],
  });
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    error: "Internal server error",
    message:
      process.env.NODE_ENV === "development"
        ? err.message
        : "Something went wrong",
  });
});

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("SIGTERM received, shutting down gracefully...");
  await mongoose.connection.close();
  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("SIGINT received, shutting down gracefully...");
  await mongoose.connection.close();
  process.exit(0);
});

// Start server
app.listen(PORT, async () => {
  console.log(`Authentication Service running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Ready to authenticate users!`);

  // Create default admin user if it doesn't exist
  try {
    const adminExists = await User.findOne({ username: "admin" });
    if (!adminExists) {
      const adminUser = new User({
        username: "admin",
        email: "admin@authservice.com",
        password: await hashPassword("admin123456"),
        role: "admin",
      });
      await adminUser.save();
      console.log("Default admin user created: admin / admin123456");
    } else {
      console.log("Admin already exist: ", adminExists.username);
    }
  } catch (error) {
    console.error("Error creating default admin:", error);
  }
});

module.exports = app;
