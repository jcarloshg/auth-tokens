As a system design expert, I view **JWT (JSON Web Tokens)** as a powerful tool for stateless authentication, but they come with significant security responsibilities. Because JWTs are "stored" on the client side, you lose the ability to instantly kill a session as you would with a server-side session ID.

Here is the architectural checklist for managing JWTs securely.

### 1. Token Anatomy & Storage

How you store and structure the token determines your vulnerability to **XSS (Cross-Site Scripting)** and **CSRF (Cross-Site Request Forgery)**.

- **Never store JWTs in LocalStorage:** LocalStorage is accessible by any JavaScript on your page. If a third-party script is compromised, your user's token is stolen.
- **Use `HttpOnly` Cookies:** Store tokens in a cookie with the `HttpOnly`, `Secure`, and `SameSite=Strict` flags. This prevents JavaScript from reading the token.
- **Keep Payloads Lean:** Don't put sensitive data (like passwords or PII) in the JWT. Anyone can decode a JWT at [jwt.io](https://jwt.io) without the secret key.

### 2. The "Dual Token" Strategy

To balance security and user experience, use two different tokens:

- **Access Token:** Short-lived (e.g., **15 minutes**). Used for every API request.
- **Refresh Token:** Long-lived (e.g., **7 days**). Used only to get a new Access Token.
- **Why?** If an Access Token is stolen, the attacker only has a 15-minute window. The Refresh Token should be stored in a database so you can **revoke** it if a user logs out or a leak is detected.

### 3. Implementation Best Practices

- **Use Strong Algorithms:** Avoid `HS256` (Symmetric) if you have multiple microservices. Use **`RS256` (Asymmetric)** so services can verify the token with a **Public Key** without knowing the **Private Key** used to sign it.
- **Explicitly Disable "none" Algorithm:** Ensure your backend library rejects tokens where the header specifies `"alg": "none"`, which is a common exploit to bypass signature verification.
- **Validate Everything:** Always check the `exp` (expiration), `iat` (issued at), and `iss` (issuer) claims on every request.

### 4. Handling Revocation (The "Stateless" Paradox)

Since JWTs are valid until they expire, "logging out" on the client doesn't stop the token from working.

- **Denylists (Blacklisting):** Store the `jti` (Unique JWT ID) of revoked tokens in a fast-access store like **Redis** until their natural expiration time.
- **Rotation:** Every time a Refresh Token is used, issue a _new_ Refresh Token and invalidate the old one. If an old one is used twice, you know a theft occurred, and you can kill all sessions for that user.

### Summary Table: JWT Best Practices

| Category       | Best Practice            | Why?                                          |
| -------------- | ------------------------ | --------------------------------------------- |
| **Storage**    | `HttpOnly` Cookie        | Prevents XSS-based token theft.               |
| **Lifespan**   | 5–15 Minute Access Token | Minimizes the "window of theft."              |
| **Signing**    | RS256 (Asymmetric)       | Safer for microservices/distributed systems.  |
| **Revocation** | Refresh Token Rotation   | Detects and stops token replay attacks.       |
| **Payload**    | Use `sub` and `jti`      | Identifies the user and the specific session. |

### The "Expert" Recommendation: Use an Identity Provider (IdP)

Unless you have a specific reason to build your own, use a battle-tested service like **Auth0**, **Clerk**, or **AWS Cognito**. They handle the complexities of token rotation, OIDC compliance, and secure storage so you don't have to.
