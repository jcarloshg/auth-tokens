import express from 'express';
import cookieParser from 'cookie-parser';
// Import route handlers
import { healthRoutes } from '@/presentation/routes/health.routes';
import { authRoutes } from '@/presentation/routes/auth.routes';
import { usersRoutes } from './presentation/routes/users.routes';

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cookieParser())

// Routes
healthRoutes(app);
authRoutes(app);
usersRoutes(app);

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
