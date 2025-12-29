import { Express, Router } from "express";
import { LoginController } from "../controller/auth/login.controller";
import { RefreshController } from "../controller/auth/refresh.controller";

export const authRoutes = (app: Express) => {
    const router = Router();

    router.post('/login', LoginController);

    router.post('/refresh', RefreshController)

    router.post('/register', (req, res) => {
        // Handle registration
        res.send('Register endpoint');
    });

    app.use('/auth', router);
}