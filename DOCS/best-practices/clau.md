# JWT Authentication - Best Practices Guide

A comprehensive guide to implementing secure JWT authentication.

---

## Core JWT Concepts

### What is JWT?

**JWT (JSON Web Token)** is a compact, self-contained token format for securely transmitting information between parties.

**Structure:**

```
header.payload.signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Parts:**

1. **Header:** Algorithm and token type
2. **Payload:** Claims (user data)
3. **Signature:** Verification signature

---

## Best Practices Checklist

### 1. **Use Strong Secret Keys** ⭐ CRITICAL

```javascript
// ❌ BAD - Weak secret
const SECRET = 'secret123';
const SECRET = 'myapp';

// ✅ GOOD - Strong, random secret
const SECRET = crypto.randomBytes(64).toString('hex');
// Result: 'a1b2c3d4e5f6....' (128+ characters)

// ✅ BEST - Use environment variables
const SECRET = process.env.JWT_SECRET;

// Generate strong secret (run once, store in .env)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

**Requirements:**

- Minimum 256 bits (32 bytes) for HS256
- Minimum 2048 bits for RS256
- Store in environment variables, NEVER in code
- Use different secrets for dev/staging/production
- Rotate secrets periodically

---

### 2. **Use Appropriate Algorithm** ⭐ CRITICAL

```javascript
// Symmetric (HMAC)
const jwt = require("jsonwebtoken");

// ✅ GOOD for single server/service
const token = jwt.sign(payload, SECRET, { algorithm: "HS256" });

// Asymmetric (RSA)
const fs = require("fs");
const privateKey = fs.readFileSync("private.key");
const publicKey = fs.readFileSync("public.key");

// ✅ BETTER for microservices/distributed systems
const token = jwt.sign(payload, privateKey, { algorithm: "RS256" });
jwt.verify(token, publicKey); // Any service can verify
```

**Algorithm Choices:**

| Algorithm | Type       | Use Case                   | Key Size   |
| --------- | ---------- | -------------------------- | ---------- |
| HS256     | Symmetric  | Single server, simple apps | 256+ bits  |
| HS512     | Symmetric  | Higher security needs      | 512+ bits  |
| RS256     | Asymmetric | Microservices, distributed | 2048+ bits |
| RS512     | Asymmetric | Highest security           | 4096+ bits |
| ES256     | Asymmetric | Performance + security     | 256 bits   |

**⚠️ NEVER use 'none' algorithm**

---

### 3. **Set Short Expiration Times**

```javascript
// ❌ BAD - Too long
const token = jwt.sign(payload, SECRET, { expiresIn: "30d" });
const token = jwt.sign(payload, SECRET); // Never expires!

// ✅ GOOD - Short-lived access tokens
const accessToken = jwt.sign(payload, SECRET, {
  expiresIn: "15m", // 15 minutes
});

// ✅ BEST - Access + Refresh token pattern
const accessToken = jwt.sign(payload, ACCESS_SECRET, {
  expiresIn: "15m",
});

const refreshToken = jwt.sign(
  { userId: user.id, tokenVersion: user.tokenVersion },
  REFRESH_SECRET,
  { expiresIn: "7d" }
);
```

**Recommended Expiration Times:**

| Token Type         | Expiration   | Storage         |
| ------------------ | ------------ | --------------- |
| Access Token       | 5-15 minutes | Memory (state)  |
| Refresh Token      | 7-30 days    | HttpOnly cookie |
| Remember Me        | 30-90 days   | Secure database |
| Email Verification | 24 hours     | Database        |
| Password Reset     | 1 hour       | Database        |

---

### 4. **Implement Refresh Token Strategy** ⭐ CRITICAL

```javascript
// Complete refresh token implementation
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET;

// Login endpoint
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validate credentials
    const user = await db.users.findOne({ email });
    if (!user) {
      return res.status(401).json({
        error: "Invalid credentials",
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid credentials",
      });
    }

    // 2. Generate tokens
    const accessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
      },
      ACCESS_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      {
        userId: user.id,
        tokenVersion: user.tokenVersion,
      },
      REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    // 3. Store refresh token in database
    await db.refreshTokens.create({
      userId: user.id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // 4. Send refresh token as HttpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // 5. Send access token in response
    res.json({
      accessToken,
      tokenType: "Bearer",
      expiresIn: 900, // 15 minutes in seconds
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Refresh endpoint
app.post("/auth/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        error: "Refresh token required",
      });
    }

    // 1. Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    } catch (err) {
      return res.status(401).json({
        error: "Invalid refresh token",
      });
    }

    // 2. Check if token exists in database
    const storedToken = await db.refreshTokens.findOne({
      userId: decoded.userId,
      token: refreshToken,
    });

    if (!storedToken) {
      return res.status(401).json({
        error: "Refresh token not found",
      });
    }

    // 3. Get user and verify token version
    const user = await db.users.findById(decoded.userId);
    if (!user || user.tokenVersion !== decoded.tokenVersion) {
      // Token version mismatch - possible token theft
      await db.refreshTokens.deleteMany({ userId: decoded.userId });
      return res.status(401).json({
        error: "Invalid token version",
      });
    }

    // 4. Generate new access token
    const accessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
      },
      ACCESS_SECRET,
      { expiresIn: "15m" }
    );

    // 5. Optionally rotate refresh token
    const newRefreshToken = jwt.sign(
      {
        userId: user.id,
        tokenVersion: user.tokenVersion,
      },
      REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    // Update refresh token in database
    await db.refreshTokens.update(
      { token: refreshToken },
      {
        token: newRefreshToken,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      }
    );

    // Update cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      accessToken,
      tokenType: "Bearer",
      expiresIn: 900,
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});
```

---

### 5. **Store Tokens Securely**

```javascript
// ❌ BAD - Vulnerable to XSS
localStorage.setItem("token", accessToken);
sessionStorage.setItem("token", accessToken);

// ✅ GOOD - HttpOnly cookies (for refresh tokens)
res.cookie("refreshToken", refreshToken, {
  httpOnly: true, // Not accessible via JavaScript
  secure: true, // HTTPS only
  sameSite: "strict", // CSRF protection
  maxAge: 7 * 24 * 60 * 60 * 1000,
});

// ✅ GOOD - Memory/state (for access tokens)
// React example
const [accessToken, setAccessToken] = useState(null);

// ✅ BEST - Combination approach
// - Access tokens in memory (lost on refresh)
// - Refresh tokens in HttpOnly cookies
// - On app load, get new access token using refresh token
```

**Storage Comparison:**

| Storage              | XSS Vulnerable | CSRF Vulnerable | Survives Refresh | Best For          |
| -------------------- | -------------- | --------------- | ---------------- | ----------------- |
| localStorage         | ✅ Yes         | ❌ No           | ✅ Yes           | ❌ Avoid          |
| sessionStorage       | ✅ Yes         | ❌ No           | ❌ No            | ❌ Avoid          |
| Memory/State         | ❌ No          | ❌ No           | ❌ No            | ✅ Access tokens  |
| HttpOnly Cookie      | ❌ No          | ⚠️ Yes          | ✅ Yes           | ✅ Refresh tokens |
| Secure Cookie + CSRF | ❌ No          | ❌ No           | ✅ Yes           | ✅ Best option    |

---

### 6. **Include Essential Claims Only**

```javascript
// ❌ BAD - Too much sensitive data
const token = jwt.sign(
  {
    userId: user.id,
    email: user.email,
    password: user.password, // NEVER include password!
    ssn: user.ssn, // NEVER include sensitive data!
    creditCard: user.creditCard, // NEVER include PII!
    privateKey: user.privateKey,
    fullProfile: user, // Too much data
  },
  SECRET
);

// ✅ GOOD - Minimal necessary claims
const token = jwt.sign(
  {
    sub: user.id, // Subject (user ID)
    email: user.email, // Email
    role: user.role, // Role for authorization
    iat: Math.floor(Date.now() / 1000), // Issued at (automatic)
  },
  SECRET,
  { expiresIn: "15m" }
);

// ✅ BETTER - Standard claims + custom
const token = jwt.sign(
  {
    // Standard claims
    sub: user.id, // Subject
    iss: "myapp.com", // Issuer
    aud: "myapp.com", // Audience
    iat: Math.floor(Date.now() / 1000), // Issued at
    exp: Math.floor(Date.now() / 1000) + 900, // Expires

    // Custom claims (minimal)
    email: user.email,
    role: user.role,
    permissions: ["read", "write"],
  },
  SECRET
);
```

**Standard JWT Claims:**

| Claim | Name       | Description       | Example     |
| ----- | ---------- | ----------------- | ----------- |
| `sub` | Subject    | User identifier   | "user-123"  |
| `iss` | Issuer     | Who created token | "myapp.com" |
| `aud` | Audience   | Who can use token | "myapp.com" |
| `exp` | Expiration | When expires      | 1735480800  |
| `iat` | Issued At  | When created      | 1735480000  |
| `nbf` | Not Before | Valid after time  | 1735480000  |
| `jti` | JWT ID     | Unique identifier | "abc-123"   |

**What to NEVER include:**

- Passwords (hashed or not)
- Social Security Numbers
- Credit card info
- Private keys
- API secrets
- Full user objects

---

### 7. **Validate Tokens Properly**

```javascript
// Authentication middleware
const authenticateToken = (req, res, next) => {
  // 1. Extract token from header
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      error: "Access token required",
    });
  }

  // 2. Verify token
  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err) {
      // Token invalid or expired
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({
          error: "Token expired",
          code: "TOKEN_EXPIRED",
        });
      }

      if (err.name === "JsonWebTokenError") {
        return res.status(403).json({
          error: "Invalid token",
          code: "INVALID_TOKEN",
        });
      }

      return res.status(403).json({
        error: "Token verification failed",
      });
    }

    // 3. Additional validation
    // Check token blacklist
    if (isTokenBlacklisted(token)) {
      return res.status(401).json({
        error: "Token revoked",
      });
    }

    // 4. Attach user to request
    req.user = decoded;
    next();
  });
};

// Usage
app.get("/api/protected", authenticateToken, (req, res) => {
  res.json({
    message: "Protected data",
    user: req.user,
  });
});
```

**Validation Checklist:**

- [ ] Verify signature
- [ ] Check expiration
- [ ] Validate issuer (iss)
- [ ] Validate audience (aud)
- [ ] Check token blacklist
- [ ] Verify token version
- [ ] Validate required claims exist

---

### 8. **Implement Token Revocation**

```javascript
// Token versioning approach
const userSchema = new Schema({
  email: String,
  password: String,
  tokenVersion: { type: Number, default: 0 },
});

// When user changes password or logs out from all devices
app.post("/auth/logout-all", authenticateToken, async (req, res) => {
  try {
    // Increment token version - invalidates all existing tokens
    await db.users.update(
      { id: req.user.userId },
      { $inc: { tokenVersion: 1 } }
    );

    // Delete all refresh tokens
    await db.refreshTokens.deleteMany({
      userId: req.user.userId,
    });

    res.json({ message: "Logged out from all devices" });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Token blacklist approach (for immediate revocation)
const redis = require("redis");
const redisClient = redis.createClient();

// Blacklist token
async function blacklistToken(token, expiresIn) {
  const decoded = jwt.decode(token);
  const ttl = decoded.exp - Math.floor(Date.now() / 1000);

  if (ttl > 0) {
    await redisClient.setex(`blacklist:${token}`, ttl, "revoked");
  }
}

// Check if blacklisted
async function isTokenBlacklisted(token) {
  const result = await redisClient.get(`blacklist:${token}`);
  return result !== null;
}

// Logout endpoint
app.post("/auth/logout", authenticateToken, async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];

    // Blacklist access token
    await blacklistToken(token, 900); // 15 min TTL

    // Remove refresh token
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      await db.refreshTokens.deleteOne({ token: refreshToken });
    }

    res.clearCookie("refreshToken");
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});
```

**Revocation Strategies:**

| Strategy          | Pros                 | Cons                      | Best For           |
| ----------------- | -------------------- | ------------------------- | ------------------ |
| Token Versioning  | Simple, no storage   | Can't revoke single token | Logout all devices |
| Blacklist (Redis) | Immediate revocation | Requires storage          | Single logout      |
| Short expiration  | No storage needed    | More token refreshes      | High security apps |
| Database lookup   | Full control         | Performance impact        | Low traffic apps   |

---

### 9. **Protect Against Common Attacks**

#### **A. XSS (Cross-Site Scripting)**

```javascript
// ✅ Prevent XSS
// 1. Don't store tokens in localStorage
// 2. Sanitize all user inputs
const sanitizeHtml = require("sanitize-html");

app.post("/api/posts", authenticateToken, (req, res) => {
  const cleanContent = sanitizeHtml(req.body.content);
  // Save cleanContent
});

// 3. Set security headers
const helmet = require("helmet");
app.use(helmet());

// 4. Content Security Policy
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
    },
  })
);
```

#### **B. CSRF (Cross-Site Request Forgery)**

```javascript
// ✅ CSRF Protection
const csrf = require("csurf");

// Enable CSRF protection
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  },
});

app.use(csrfProtection);

// Send CSRF token to client
app.get("/auth/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Client includes CSRF token in requests
// fetch('/api/data', {
//   method: 'POST',
//   headers: { 'X-CSRF-Token': csrfToken }
// });
```

#### **C. Token Sidejacking/Theft**

```javascript
// ✅ Bind token to client
const crypto = require("crypto");

// Generate fingerprint
function generateFingerprint(req) {
  const components = [
    req.ip,
    req.headers["user-agent"],
    req.headers["accept-language"],
  ];

  return crypto.createHash("sha256").update(components.join("|")).digest("hex");
}

// Include in token
app.post("/auth/login", (req, res) => {
  const fingerprint = generateFingerprint(req);

  const token = jwt.sign(
    {
      userId: user.id,
      fingerprint: fingerprint,
    },
    SECRET,
    { expiresIn: "15m" }
  );

  // Store fingerprint in httpOnly cookie
  res.cookie("__Secure-Fgp", fingerprint, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });

  res.json({ accessToken: token });
});

// Validate fingerprint
const validateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  const storedFingerprint = req.cookies["__Secure-Fgp"];

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });

    // Verify fingerprint
    if (decoded.fingerprint !== storedFingerprint) {
      return res.status(403).json({
        error: "Token fingerprint mismatch",
      });
    }

    req.user = decoded;
    next();
  });
};
```

#### **D. Timing Attacks**

```javascript
// ✅ Use constant-time comparison
const crypto = require("crypto");

function safeCompare(a, b) {
  // Use crypto.timingSafeEqual for constant-time comparison
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  if (bufA.length !== bufB.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

// Use in token validation
if (!safeCompare(providedToken, expectedToken)) {
  return res.status(401).json({ error: "Invalid token" });
}
```

---

### 10. **Implement Rate Limiting**

```javascript
const rateLimit = require("express-rate-limit");
const RedisStore = require("rate-limit-redis");
const redis = require("redis");

const redisClient = redis.createClient();

// Strict rate limit for auth endpoints
const authLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: "rl:auth:",
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: "Too many authentication attempts, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: "Too many requests",
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000),
    });
  },
});

// Apply to auth routes
app.post("/auth/login", authLimiter, loginHandler);
app.post("/auth/refresh", authLimiter, refreshHandler);

// Progressive delay for failed attempts
const loginAttempts = new Map();

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const attempts = loginAttempts.get(email) || 0;

  // Progressive delay: 0s, 1s, 2s, 4s, 8s...
  if (attempts > 0) {
    const delay = Math.min(Math.pow(2, attempts - 1) * 1000, 30000);
    await new Promise((resolve) => setTimeout(resolve, delay));
  }

  const user = await db.users.findOne({ email });
  const validPassword = user && (await bcrypt.compare(password, user.password));

  if (!validPassword) {
    loginAttempts.set(email, attempts + 1);

    // Clear after 1 hour
    setTimeout(() => loginAttempts.delete(email), 60 * 60 * 1000);

    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Success - clear attempts
  loginAttempts.delete(email);

  // Generate tokens...
});
```

---

### 11. **Use HTTPS Only**

```javascript
// ✅ Force HTTPS in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production" && !req.secure) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// ✅ Set secure cookie flags
res.cookie("refreshToken", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production", // HTTPS only
  sameSite: "strict",
});

// ✅ HSTS Header (HTTP Strict Transport Security)
app.use((req, res, next) => {
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );
  next();
});
```

---

### 12. **Implement Proper Error Handling**

```javascript
// ❌ BAD - Leaks information
jwt.verify(token, SECRET, (err, decoded) => {
  if (err) {
    return res.status(403).json({
      error: err.message, // "jwt malformed", "invalid signature"
      stack: err.stack, // NEVER expose stack traces!
    });
  }
});

// ✅ GOOD - Generic error messages
jwt.verify(token, SECRET, (err, decoded) => {
  if (err) {
    // Log detailed error server-side
    logger.error("JWT verification failed", {
      error: err.message,
      token: token.substring(0, 10) + "...", // Partial token for debugging
    });

    // Return generic error to client
    return res.status(401).json({
      error: "Authentication failed",
      code: "AUTH_ERROR",
    });
  }

  req.user = decoded;
  next();
});

// ✅ BETTER - Specific error codes without details
const handleJWTError = (err, res) => {
  const errorResponses = {
    TokenExpiredError: {
      status: 401,
      code: "TOKEN_EXPIRED",
      message: "Token has expired",
    },
    JsonWebTokenError: {
      status: 401,
      code: "INVALID_TOKEN",
      message: "Invalid token",
    },
    NotBeforeError: {
      status: 401,
      code: "TOKEN_NOT_ACTIVE",
      message: "Token not yet valid",
    },
  };

  const errorResponse = errorResponses[err.name] || {
    status: 401,
    code: "AUTH_ERROR",
    message: "Authentication failed",
  };

  // Log detailed error
  logger.error("JWT Error", {
    type: err.name,
    message: err.message,
    timestamp: new Date().toISOString(),
  });

  res.status(errorResponse.status).json({
    error: errorResponse.message,
    code: errorResponse.code,
  });
};
```

---

### 13. **Monitor and Log JWT Usage**

```javascript
const winston = require("winston");

const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  transports: [new winston.transports.File({ filename: "auth.log" })],
});

// Log successful authentications
app.post("/auth/login", async (req, res) => {
  // ... authentication logic ...

  logger.info("User logged in", {
    userId: user.id,
    email: user.email,
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    timestamp: new Date().toISOString(),
  });

  // Send tokens...
});

// Log failed attempts
app.post("/auth/login", async (req, res) => {
  if (!validPassword) {
    logger.warn("Failed login attempt", {
      email: req.body.email,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      timestamp: new Date().toISOString(),
    });
  }
});

// Log token refresh
app.post("/auth/refresh", async (req, res) => {
  logger.info("Token refreshed", {
    userId: decoded.userId,
    ip: req.ip,
    timestamp: new Date().toISOString(),
  });
});

// Monitor suspicious activity
const detectSuspiciousActivity = async (userId) => {
  const recentLogins = await db.logs.find({
    userId,
    event: "login",
    timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) },
  });

  // Multiple IPs in short time
  const uniqueIPs = new Set(recentLogins.map((l) => l.ip));
  if (uniqueIPs.size > 3) {
    logger.alert("Suspicious activity detected", {
      userId,
      uniqueIPs: Array.from(uniqueIPs),
      count: recentLogins.length,
    });

    // Send alert to user
    await sendSecurityAlert(userId, "Multiple login locations detected");
  }
};
```

---

### 14. **Implement Multi-Factor Authentication (MFA)**

```javascript
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Enable MFA for user
app.post('/auth/mfa/enable', authenticateToken, async (req, res) => {
  try {
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `MyApp (${req.user.email})`
    });

    // Store secret temporarily (not confirmed yet)
    await db.users.update(
      { id: req.user.userId },
      { mfaSecretTemp: secret.base32 }
    );

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json({
      secret: secret.base32,
      qrCode: qrCodeUrl
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to enable MFA' });
  }
});

// Verify and confirm MFA
app.post('/auth/mfa/verify', authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;
    const user = await db.users.findById(req.user.userId);

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecretTemp,
      encoding: 'base32',
      token: token,
      window: 2 // Allow 2 time steps before/after
    });

    if (!verified) {
      return res.status(400).json({
        error: 'Invalid verification code'
      });
    }

    // Confirm MFA
    await db.users.update(
      { id: req.user.userId },
      {
        mfaSecret: user.mfaSecretTemp,
        mfaEnabled: true,
        mfaSecretTemp: null
      }
    );

    //
```
