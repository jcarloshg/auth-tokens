import { Express, Router } from "express";

export const authRoutes = (app: Express) => {
    const router = Router();

    router.post('/login', (req, res) => {
        // Handle login
        res.send('Login endpoint');
    });

    router.post('/register', (req, res) => {
        // Handle registration
        res.send('Register endpoint');
    });

    app.use('/auth', router);
}