import { Key } from "cose-js";
import { Resolver } from "did-resolver";
import { getResolver as getWebResolver } from "web-did-resolver";

const webResolver = getWebResolver();
const didResolver = new Resolver({...webResolver});

function fromJsonWebKey(key: JsonWebKey) : Key {
    return {
        crv: key.crv,
        kty: key.kty,
        k: key.k ? Buffer.from(key.k, 'base64url').toString("hex") : undefined,
        d: key.d ? Buffer.from(key.d, 'base64url').toString("hex") : undefined,
        x: key.x ? Buffer.from(key.x, 'base64url').toString("hex") : undefined,
        y: key.y ? Buffer.from(key.y, 'base64url').toString("hex") : undefined,
    }
}

export async function resolvePublicKey(reference: string) : Promise<Key | undefined> {
    const did = await didResolver.resolve(reference);
    if (!did.didDocument.assertionMethod?.includes(reference)) {
        return undefined;
    }

    const verificationMethod = did.didDocument.verificationMethod.find(v => v.id === reference);
    if (!verificationMethod || verificationMethod.type !== "JsonWebKey2020") {
        return undefined;
    }

    return fromJsonWebKey(verificationMethod.publicKeyJwk);
}