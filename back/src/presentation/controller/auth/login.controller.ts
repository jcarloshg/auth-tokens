import { JwtService } from "@/app/shared/domain/services/JwtService";
import { singInApplication } from "@/app/sing-in/application/sing-in.application";
import { SingInRequestProps, SingInResponseProps } from "@/app/sing-in/domain/sing-in.usecase";
import { Request, Response } from "express";

export const LoginController = async (req: Request, res: Response) => {

    // create request props
    const singInRequestProps: SingInRequestProps = { body: req.body }
    const customResponse = await singInApplication(singInRequestProps);

    // make response with cookie
    const customResponseProps = customResponse.props;
    if (customResponseProps.data) {
        const data = customResponseProps.data as SingInResponseProps;
        const resToSend = {
            auth: {
                accessToken: data.auth.accessToken,
                tokenType: data.auth.tokenType,
                expiresIn: data.auth.expiresIn,
            },
            data: data.data,
        }
        res.cookie(
            "refreshToken",
            data.auth.refreshToken,
            {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict",
                maxAge: JwtService.REFRESH_TOKEN_EXPIRES,
            }
        );
        res.status(customResponseProps.statusCode).json(resToSend);
        return;
    }

    res.status(customResponseProps.statusCode).json(customResponseProps);
    return;
}