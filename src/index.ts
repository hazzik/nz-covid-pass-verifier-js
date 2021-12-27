import base32Decode = require("base32-decode");
import cbor = require("cbor");
import uuid = require("uuid");
import { sign } from "cose-js";
import { VerifierOptions } from "./VerifierOptions";
import { resolvePublicKey } from "./resolvePublicKey";
import { parseQRCode } from "./parseQrCode";

const claims = {1: 'iss', 2: 'sub', 3: 'aud', 4: 'exp', 5: 'nbf', 6: 'iat', 7: 'jti'};
const requiredClaims = ["iss", "nbf", "exp", "vc"];
const headers = {1: 'alg', 4: 'kid'}

function addBase32Padding(input: string): string {
    let result = input;
    while ((result.length % 8) !== 0) {
        result += '=';
    }
    return result;
}

function toJwt(token: Map<any, any>): any {
    let jwt = {};
    for (const key of token.keys()) {
        const claimName = claims[key] ?? key;
        jwt[claimName] = claimName == 'jti' ? `urn:uuid:${uuid.stringify(token.get(key))}` : token.get(key);
    }
    return jwt;
}

function validJwt(jwt: any) : boolean {
    const keys = Object.keys(jwt);

    if (!requiredClaims.every(c => keys.includes(c))) {
        return false;
    }

    if (jwt.exp < Math.floor(Date.now() / 1000)) {
        return false;
    }

    if (jwt.nbf > Math.floor(Date.now() / 1000)) {
        return false;
    }

    return true;
}

function toJson(header: Map<any, any>): any {
    let json = {};
    for (const key of header.keys()) {
        const name = headers[key] ?? key;
        const value = header.get(key);
        json[name] = value instanceof Buffer ? value.toString('utf8') : value;
    }
    return json;
}

export class Verifier {
    trustedIssuers: string[];

    constructor(options?: VerifierOptions) {
        this.trustedIssuers = options?.trustedIssuers ?? ["did:web:nzcp.identity.health.nz"];
    }

    isTrusted(iss: string) {
        return this.trustedIssuers.includes(iss);
    }

    public async verify(message: string): Promise<boolean> {
        const decodedPayload = parseQRCode(message);
        if (!decodedPayload) {
            return false;
        }

        const coseSign1 = await cbor.decodeFirst(decodedPayload);
        if (!(coseSign1 instanceof cbor.Tagged) && coseSign1.tag !== 18) {
            return false;
        }

        const header = toJson(await cbor.decodeFirst(coseSign1.value[0]));

        const cwt = await cbor.decodeFirst(coseSign1.value[2]);
        const jwt = toJwt(cwt);

        if (!this.isTrusted(jwt.iss) || !validJwt(jwt)) {
            return false;
        }
        
        const key = await resolvePublicKey(`${jwt.iss}#${header.kid}`);
        if (!key) {
            return false;
        }

        try {
            await sign.verify(decodedPayload, {key});
            return true;
        } catch (e) {
            return false;
        }
    }
}
