import { refreshTokenApplication } from "@/app/refresh-token/app/refresh-token.app";
import { RefreshTokenUseCaseProps, RefreshTokenUseCaseResponse } from "@/app/refresh-token/domain/refresh-token.use-case";
import { JwtService } from "@/app/shared/domain/services/JwtService";
import { Request, Response } from "express";

export const RefreshController = async (req: Request, res: Response) => {
    console.log(`req.cookies`, req.cookies.refreshToken);

    const props: RefreshTokenUseCaseProps = {
        refreshToken: req.cookies.refreshToken ?? ""
    }
    const customResponse = await refreshTokenApplication(props);


    // make response with cookie
    const customResponseProps = customResponse.props;
    if (customResponseProps.data) {
        const data = customResponseProps.data as RefreshTokenUseCaseResponse;
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
};
