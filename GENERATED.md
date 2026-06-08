# Generated distribution

This folder is a generated GitHub Marketplace distribution for the obfuscan action.

Do not maintain copied rules or bundled JavaScript by hand. Regenerate everything from the main obfuscan repository:

```bash
cd packages/action
npm run marketplace
```

Source of truth:

- `packages/action/src` for action behavior.
- `packages/rules/languages` for rule JSON.
- `packages/core/src` for scanner behavior.

GitHub Actions does not run `npm install` for JavaScript actions, so `dist/` intentionally contains the bundled runtime files needed by Marketplace users.

