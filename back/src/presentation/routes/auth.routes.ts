import { singInApplication } from "@/app/sing-in/application/sing-in.application";
import { SingInRequestProps } from "@/app/sing-in/domain/sing-in.usecase";
import { Express, Router } from "express";

export const authRoutes = (app: Express) => {
    const router = Router();

    router.post('/login', async (req, res) => {
        console.log(`req.body: ${JSON.stringify(req.body)}`);
        const singInRequestProps: SingInRequestProps = {
            body: req.body
        }
        const customResponse = await singInApplication(singInRequestProps);
        const customResponseProps = customResponse.props;
        res.status(customResponseProps.statusCode).json(customResponseProps);
    });

    router.post('/register', (req, res) => {
        // Handle registration
        res.send('Register endpoint');
    });

    app.use('/auth', router);
}