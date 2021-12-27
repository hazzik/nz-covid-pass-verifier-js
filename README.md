# NZ Covid Pass Verifier

TypeScript implementation of [NZ COVID Pass - Technical Specification v1](https://nzcp.covid19.health.nz/).

## Installation

```sh
npm install --save nz-covid-pass-verifier
```

Or if you prefer to use Yarn:

```sh
yarn add nz-covid-pass-verifier
```

## Usage

```typescript
import { Verifier } from "nz-covid-pass-verifier";

let uri = "NZCP:/1/2KCE3IQEJB5DCMSLMY3....";

new Verifier().verify(uri).then(result => {
    console.log(result);
});
```