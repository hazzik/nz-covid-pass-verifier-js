import base32Decode = require("base32-decode");

function addBase32Padding(input: string): string {
    let result = input;
    while ((result.length % 8) !== 0) {
        result += '=';
    }
    return result;
}

export function parseQRCode(qrCode: string) : ArrayBuffer | undefined {
    const [schema, version, payload] = qrCode.split("/");
    if (schema !== "NZCP:" || version !== "1") {
        return undefined;
    }

    const paddedPayload = addBase32Padding(payload);
    return base32Decode(paddedPayload, 'RFC4648');
}