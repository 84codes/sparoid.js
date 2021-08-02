# SPAroid

JavaScript/NodeJS implemention of the SPAroid client. 

## Usage

```javascript
import Sparoid from '@84codes/sparoid'

// Sparoid will read the environment variables SPAROID_KEY and SPAROID_HMAC_KEY
await new Sparoid(host, port).auth()

// alternatively
await new Sparoid(host, port, key, hmac_key).auth()
```
