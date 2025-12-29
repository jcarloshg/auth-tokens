import {
    JwtService,
    SingProps,
    SignResponse,
} from "@/app/shared/domain/services/JwtService";
import jwt, { SignOptions, VerifyOptions, JwtPayload } from "jsonwebtoken";

export class JwtWebToken implements JwtService {
    // In real scenarios, use environment variables
    private readonly ACCESS_SECRET: string = "secret_word";
    private readonly REFRESH_SECRET: string = "refresh_secret_word";

    // constructor(secret: string) {
    //     this.secret = secret;
    // }

    public sign(props: JwtWebTokenSignProps): SignResponse {
        const payload = props.payload;
        const accessToken = jwt.sign(
            payload,
            this.ACCESS_SECRET,
            {
                algorithm: "HS256",
                expiresIn: JwtService.ACCESS_TOKEN_EXPIRES,
            }
        );
        const refreshToken = jwt.sign(
            {
                userId: props.userId,
            },
            this.REFRESH_SECRET,
            {
                algorithm: "HS256",
                expiresIn: JwtService.REFRESH_TOKEN_EXPIRES,
            }
        );
        const signResponse: SignResponse = {
            accessToken: accessToken,
            refreshToken: refreshToken,
            tokenType: "Bearer",
            expiresIn: JwtService.ACCESS_TOKEN_EXPIRES,
        };
        return signResponse;
    }

    public verifyRefreshToken(refreshToken: string): string {
        const options: VerifyOptions = {};
        const jwtPayload = jwt.verify(refreshToken, this.REFRESH_SECRET, options);
        console.log(`jwtPayload: ${jwtPayload}`);
        return "jwtPayload";
    }

    public decode(token: string): null | { [key: string]: any } | string {
        return jwt.decode(token);
    }
}

export interface JwtWebTokenSignProps extends SingProps {
    userId: string;
}
