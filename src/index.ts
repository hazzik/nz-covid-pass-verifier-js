import cbor = require("cbor");
import { VerifierOptions } from "./VerifierOptions";
import { resolvePublicKey } from "./resolvePublicKey";
import { parseURI } from "./parseURI";
import { PublicCovidPass } from "./PublicCovidPass";
import { toJwt } from "./toJwt";
import { verifySignature } from "./verifySignature";

const requiredClaims = ["iss", "nbf", "exp", "vc"];
const headers = { alg: 1, kid: 4 };

function validJwt(jwt: any): boolean {
    const keys = Object.keys(jwt);

    if (!requiredClaims.every((c) => keys.includes(c))) {
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

export class Verifier {
    trustedIssuers: string[];

    constructor(options?: VerifierOptions) {
        this.trustedIssuers = options?.trustedIssuers ?? [
            "did:web:nzcp.identity.health.nz",
        ];
    }

    isTrusted(iss: string) {
        return this.trustedIssuers.includes(iss);
    }

    public async verify(message: string): Promise<PublicCovidPass | undefined> {
        const decodedPayload = parseURI(message);
        if (!decodedPayload) {
            return undefined;
        }

        const coseSign1 = await cbor.decodeFirst(decodedPayload);
        if (!(coseSign1 instanceof cbor.Tagged) && coseSign1.tag !== 18) {
            return undefined;
        }

        const header = await cbor.decodeFirst(coseSign1.value[0]);
        const cwt = await cbor.decodeFirst(coseSign1.value[2]);
        const jwt = toJwt(cwt);

        if (!this.isTrusted(jwt.iss) || !validJwt(jwt)) {
            return undefined;
        }

        const key = await resolvePublicKey(
            `${jwt.iss}#${header.get(headers.kid)}`
        );
        if (!key) {
            return undefined;
        }

        if (!(await verifySignature(decodedPayload, key))) {
            return undefined;
        }

        return jwt;
    }
}
