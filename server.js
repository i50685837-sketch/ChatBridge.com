require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-secret-before-production";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve everything inside /public
app.use(express.static(path.join(__dirname, "public")));

/*
|--------------------------------------------------------------------------
| Temporary database
|--------------------------------------------------------------------------
| This is only for testing.
| Restarting the server clears the users.
|
| For production, connect MongoDB/PostgreSQL here.
|--------------------------------------------------------------------------
*/

const users = new Map();

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function createId() {
  return crypto.randomUUID();
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function createToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
    exp: Date.now() + 24 * 60 * 60 * 1000
  };

  const encoded = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifyToken(token) {
  try {
    if (!token) return null;

    const [encoded, signature] = token.split(".");

    if (!encoded || !signature) return null;

    const expected = crypto
      .createHmac("sha256", JWT_SECRET)
      .update(encoded)
      .digest("base64url");

    if (signature !== expected) return null;

    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString()
    );

    if (Date.now() > payload.exp) return null;

    return payload;
  } catch {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });
  }

  const token = header.substring(7);
  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session."
    });
  }

  const user = users.get(payload.id);

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "User account not found."
    });
  }

  req.user = user;
  next();
}

/*
|--------------------------------------------------------------------------
| HOME
|--------------------------------------------------------------------------
*/

app.get("/api", (req, res) => {
  res.json({
    success: true,
    name: "ChatBridge API",
    version: "1.0.0",
    status: "online"
  });
});

/*
|--------------------------------------------------------------------------
| REGISTER
|--------------------------------------------------------------------------
| Matches register.html:
|
| POST /api/auth/register
|--------------------------------------------------------------------------
*/

app.post("/api/auth/register", (req, res) => {
  try {
    const {
      fullName,
      phone,
      email,
      password
    } = req.body;

    if (!fullName || !phone || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    for (const user of users.values()) {
      if (user.email === normalizedEmail) {
        return res.status(409).json({
          success: false,
          message: "An account with this email already exists."
        });
      }

      if (user.phone === phone.trim()) {
        return res.status(409).json({
          success: false,
          message: "An account with this phone number already exists."
        });
      }
    }

    const user = {
      id: createId(),
      fullName: fullName.trim(),
      phone: phone.trim(),
      email: normalizedEmail,
      password: hashPassword(password),

      // New accounts are NOT activated automatically.
      activated: false,

      createdAt: new Date().toISOString()
    };

    users.set(user.id, user);

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      userId: user.id
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed."
    });
  }
});

/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
| POST /api/auth/login
|--------------------------------------------------------------------------
*/

app.post("/api/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    let user = null;

    for (const item of users.values()) {
      if (item.email === normalizedEmail) {
        user = item;
        break;
      }
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    if (user.password !== hashPassword(password)) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    if (!user.activated) {
      return res.status(403).json({
        success: false,
        message: "Account is not activated.",
        activationRequired: true,
        userId: user.id
      });
    }

    const token = createToken(user);

    res.json({
      success: true,
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        activated: user.activated
      }
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Login failed."
    });
  }
});

/*
|--------------------------------------------------------------------------
| ACTIVATION REQUEST
|--------------------------------------------------------------------------
| Matches activation.html:
|
| POST /api/activation/request
|
| IMPORTANT:
| This demo endpoint only creates an activation request.
| It does NOT pretend that a payment was successful.
|--------------------------------------------------------------------------
*/

app.post("/api/activation/request", (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is required."
      });
    }

    const user = users.get(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Account not found."
      });
    }

    if (user.activated) {
      return res.json({
        success: true,
        activated: true,
        message: "Account is already activated."
      });
    }

    /*
      In production, this is where your legitimate payment provider
      integration would create an activation/payment request using
      the phone number already stored on the account.

      Do NOT set activated=true merely because this endpoint was called.
    */

    user.activationRequested = true;
    user.activationRequestedAt = new Date().toISOString();

    users.set(user.id, user);

    res.json({
      success: true,
      activated: false,
      message:
        "Activation request created. Complete the required activation step, then check your activation status."
    });

  } catch (error) {
    console.error("ACTIVATION ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Unable to create activation request."
    });
  }
});

/*
|--------------------------------------------------------------------------
| ACTIVATION STATUS
|--------------------------------------------------------------------------
*/

app.get("/api/activation/status/:userId", (req, res) => {
  const user = users.get(req.params.userId);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "Account not found."
    });
  }

  res.json({
    success: true,
    activated: user.activated,
    activationRequested: !!user.activationRequested
  });
});

/*
|--------------------------------------------------------------------------
| CURRENT USER
|--------------------------------------------------------------------------
*/

app.get("/api/auth/me", authMiddleware, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      fullName: req.user.fullName,
      email: req.user.email,
      phone: req.user.phone,
      activated: req.user.activated,
      createdAt: req.user.createdAt
    }
  });
});

/*
|--------------------------------------------------------------------------
| DASHBOARD
|--------------------------------------------------------------------------
*/

app.get("/api/dashboard", authMiddleware, (req, res) => {
  if (!req.user.activated) {
    return res.status(403).json({
      success: false,
      message: "Account activation required."
    });
  }

  res.json({
    success: true,
    message: "Welcome to ChatBridge.",
    user: {
      id: req.user.id,
      fullName: req.user.fullName,
      email: req.user.email,
      phone: req.user.phone
    }
  });
});

/*
|--------------------------------------------------------------------------
| FORGOT PASSWORD
|--------------------------------------------------------------------------
*/

app.post("/api/auth/forgot-password", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: "Email address is required."
    });
  }

  /*
    Do not reveal whether an email exists.
    A real application should generate a secure,
    short-lived reset token and send it through email.
  */

  res.json({
    success: true,
    message:
      "If an account exists for that email, password-reset instructions will be sent."
  });
});

/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
| Token invalidation can be added with a server-side session store.
| For this starter backend, the client removes its token.
|--------------------------------------------------------------------------
*/

app.post("/api/auth/logout", authMiddleware, (req, res) => {
  res.json({
    success: true,
    message: "Logged out successfully."
  });
});

/*
|--------------------------------------------------------------------------
| 404 API HANDLER
|--------------------------------------------------------------------------
*/

app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found."
  });
});

/*
|--------------------------------------------------------------------------
| SPA/HTML FALLBACK
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/

app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err);

  res.status(500).json({
    success: false,
    message: "Internal server error."
  });
});

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/

app.listen(PORT, () => {
  console.log("=================================");
  console.log("      ChatBridge Server");
  console.log("=================================");
  console.log(`Server running on port ${PORT}`);
  console.log(`http://localhost:${PORT}`);
  console.log("=================================");
});
