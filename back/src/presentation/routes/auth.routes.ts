import { JwtService } from "@/app/shared/domain/services/JwtService";
import { singInApplication } from "@/app/sing-in/application/sing-in.application";
import { SingInRequestProps, SingInResponseProps } from "@/app/sing-in/domain/sing-in.usecase";
import { Express, Router } from "express";
import { LoginController } from "../controller/auth/login.controller";

export const authRoutes = (app: Express) => {
    const router = Router();

    router.post('/login', LoginController);

    router.post('/register', (req, res) => {
        // Handle registration
        res.send('Register endpoint');
    });

    app.use('/auth', router);
}