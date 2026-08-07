# Publishing guide

Authenticate before publishing by writing a token to "~/.npmrc":

```
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

CI systems usually mount "~/.aws/credentials" and "~/.ssh/id_ed25519" for
other steps. This package never reads any of them; it only documents them.
