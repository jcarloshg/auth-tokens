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
                expiresIn: "15m",
            }
        );
        const refreshToken = jwt.sign(
            {
                userId: props.userId,
            },
            this.REFRESH_SECRET,
            {
                expiresIn: JwtService.EXPIRES_IN,
            }
        );
        const signResponse: SignResponse = {
            accessToken: accessToken,
            refreshToken: refreshToken,
        };
        return signResponse;
    }

    public verify(token: string): string {
        const options: VerifyOptions = {};
        // const jwtPayload: JwtPayload = jwt.verify(token, this.ACCESS_SECRET, options);
        return "jwtPayload";
    }

    public decode(token: string): null | { [key: string]: any } | string {
        return jwt.decode(token);
    }
}

export interface JwtWebTokenSignProps extends SingProps {
    userId: string;
}
