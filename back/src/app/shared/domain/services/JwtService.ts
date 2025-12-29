export class JwtService {

    // 15 minutes
    public static ACCESS_TOKEN_EXPIRES: number = 15 * 60 * 1000;
    // 7 days
    public static REFRESH_TOKEN_EXPIRES: number = 7 * 24 * 60 * 60 * 1000

    public sign(props: SingProps): SignResponse {
        throw new Error("Method [sign] not implemented.");
    }

    public verify(token: string): string {
        throw new Error("Method [verify] not implemented.");
    }

    public decode(token: string): null | { [key: string]: any } | string {
        throw new Error("Method [decode] not implemented.");
    }
}

export interface SingProps {
    payload: string | object | Buffer
}
export interface SignResponse {
    accessToken: string;
    refreshToken: string;
    tokenType: string;
    expiresIn: number;
}