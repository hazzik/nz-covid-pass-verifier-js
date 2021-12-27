import { Key } from "cose-js";
import { Resolver } from "did-resolver";
import { getResolver as getWebResolver } from "web-did-resolver";

const webResolver = getWebResolver();
const didResolver = new Resolver({ ...webResolver });

function fromJsonWebKey(key: JsonWebKey): Key {
    return {
        crv: key.crv,
        kty: key.kty,
        k: base64urlToHex(key.k),
        d: base64urlToHex(key.d),
        x: base64urlToHex(key.x),
        y: base64urlToHex(key.y),
    };
}

function base64urlToHex(n: string): string {
    if (n) {
        return Buffer.from(n, "base64url").toString("hex");
    }

    return undefined;
}

export async function resolvePublicKey(
    reference: string
): Promise<Key | undefined> {
    const did = await didResolver.resolve(reference);
    if (!did.didDocument.assertionMethod?.includes(reference)) {
        return undefined;
    }

    const verificationMethod = did.didDocument.verificationMethod.find(
        (v) => v.id === reference
    );
    if (!verificationMethod || verificationMethod.type !== "JsonWebKey2020") {
        return undefined;
    }

    return fromJsonWebKey(verificationMethod.publicKeyJwk);
}
