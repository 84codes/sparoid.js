# SPAroid

JavaScript/NodeJS implemention of the SPAroid client. 

## Usage

```javascript
import * as sparoid from 'sparoid'

// Sparoid will read the environment variables SPAROID_KEY and SPAROID_HMAC_KEY
await sparoid.auth(host, port, key, hmac_key)

// alternatively
await sparoid.auth(host, port)
```

Or in CommonJS environments:

```javascript
import('@84codes/sparoid').then((sparoid) => {
  sparoid.auth(host, port).then(() => { console.log("authed") })
})
```
