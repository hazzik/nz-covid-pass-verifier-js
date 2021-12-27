import base32Decode = require("base32-decode");
import cbor = require("cbor");
import uuid = require("uuid");
import { Resolver } from "did-resolver";
import { getResolver } from "web-did-resolver";
import { sign } from "cose-js";
import { VerifierOptions } from "./VerifierOptions";

const webResolver = getResolver();
const didResolver = new Resolver({...webResolver});

const claims = {1: 'iss', 2: 'sub', 3: 'aud', 4: 'exp', 5: 'nbf', 6: 'iat', 7: 'cti'};
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
        jwt[claimName] = claimName == 'cti' ? `urn:uuid:${uuid.stringify(token.get(key))}` : token.get(key);
    }
    return jwt;
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

    public async verify(message: string): Promise<boolean> {
        const [schema, version, payload] = message.split("/");
        if (schema !== "NZCP:" || version !== "1") {
            return false;
        }

        const paddedPayload = addBase32Padding(payload);
        const decodedPayload = base32Decode(paddedPayload, 'RFC4648');
        const coseSign1 = await cbor.decodeFirst(decodedPayload);
        if (!(coseSign1 instanceof cbor.Tagged) && coseSign1.tag !== 18) {
            return false;
        }

        const header = toJson(await cbor.decodeFirst(coseSign1.value[0]));

        const cwt = await cbor.decodeFirst(coseSign1.value[2]);
        const jwt = toJwt(cwt);
        if (!requiredClaims.every(claim => Object.keys(jwt).includes(claim))) {
            return false;
        }

        if (jwt.exp < Math.floor(Date.now() / 1000)) {
            return false;
        }

        if (jwt.nbf > Math.floor(Date.now() / 1000)) {
            return false;
        }

        if (!this.trustedIssuers.includes(jwt.iss)) {
            return false;
        }

        const did = await didResolver.resolve(jwt.iss);
        if (!did.didDocument.assertionMethod?.includes(`${jwt.iss}#${header.kid}`)) {
            return false;
        }

        const verificationMethod = did.didDocument.verificationMethod.find(v => v.id === `${jwt.iss}#${header.kid}`);
        if (!verificationMethod || verificationMethod.type !== "JsonWebKey2020") {
            return false;
        }

        const key = {
            x: Buffer.from(verificationMethod.publicKeyJwk.x, 'base64url'),
            y: Buffer.from(verificationMethod.publicKeyJwk.y, 'base64url'),
        }

        try {
            await sign.verify(decodedPayload, {key});
            return true;
        } catch (e) {
            return false;
        }
    }
}