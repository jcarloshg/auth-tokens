export interface CustomResponseProps {
    statusCode: number;
    message: string;
    data?: any;
}

export class CustomResponse {
    constructor(public props: CustomResponseProps) { }

    // success 200
    static ok(message: string = "OK", data?: any): CustomResponse {
        return new CustomResponse({
            statusCode: 200,
            message,
            data,
        });
    }

    // create 
    static create(data: any, message: string = "Created"): CustomResponse {
        return new CustomResponse({
            statusCode: 201,
            message,
            data,
        });
    }

    // error 400
    static badRequest(message: string = "Bad Request"): CustomResponse {
        return new CustomResponse({
            statusCode: 400,
            message,
        });
    }

    // error for validation
    static validationError(message: string = "Validation Error", data?: any): CustomResponse {
        return new CustomResponse({
            statusCode: 422,
            message,
            data,
        });
    }

    // error 404
    static notFound(message: string = "Not Found"): CustomResponse {
        return new CustomResponse({
            statusCode: 404,
            message,
        });
    }

    // error 500
    static internalError(message: string = "Internal Server Error"): CustomResponse {
        return new CustomResponse({
            statusCode: 500,
            message,
        });
    }


}