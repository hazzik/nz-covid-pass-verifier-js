import { Key, sign } from "cose-js";

export async function verifySignature(payload: ArrayBuffer, key: Key) {
    try {
        await sign.verify(payload, { key });
        return true;
    } catch (e) {
        return false;
    }
}
