import { CustomResponse } from "./CustomResponse";

export type ErrosObject = { [key: string]: string };

export class ValidationError extends Error {

    private _errosObject: ErrosObject;

    constructor(message: string, errosObject: ErrosObject) {
        super(message);
        this.name = "ValidationError";
        this._errosObject = errosObject;
    }

    public getCustomResponse(): CustomResponse {
        return CustomResponse.validationError(this.message, this._errosObject);
    }
}