export interface PublicCovidPass {
    iss: string;
    nbf: number;
    exp: number;
    vc: {
        "@context": string[];
        version: string;
        type: string[];
        credentialSubject: {
            givenName: string;
            familyName: string;
            dob: string;
        };
    };
    jti?: string;
}
