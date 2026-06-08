# Contributing

The source for this action lives in the main obfuscan repository:

<https://github.com/ByteBardOrg/obfuscan/tree/main/packages/action>

Open code changes, rule updates, false positives, and bypass reports there. This Marketplace repository is intended to hold generated distribution files: `action.yml`, `dist/index.js`, and bundled rule files.

Useful local checks in the source repository:

```bash
cd packages/action
npm ci --legacy-peer-deps
npm run marketplace
npm test
```

