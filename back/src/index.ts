import express from 'express';
// Import route handlers
import { healthRoutes } from './presentation/routes/health.routes';
import { authRoutes } from './presentation/routes/auth.routes';

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Routes
healthRoutes(app);
authRoutes(app);

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
