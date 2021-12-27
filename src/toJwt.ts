import uuid = require("uuid");
import { PublicCovidPass } from "./PublicCovidPass";

const claims = {1: 'iss', 2: 'sub', 3: 'aud', 4: 'exp', 5: 'nbf', 6: 'iat', 7: 'cti'};

export function toJwt(token: Map<any, any>): PublicCovidPass {
    const jwt: any = {};
    for (const key of token.keys()) {
        const claimName = claims[key] ?? key;
        if (claimName === 'cti') {
            const jti = 'jti';
            jwt[jti] = `urn:uuid:${uuid.stringify(token.get(key))}`;
        } else {
            jwt[claimName] = token.get(key);
        }
    }

    return jwt;
}
