# Release Process

This project uses [Changesets](https://github.com/changesets/changesets) to manage versioning and releases.

## Overview

1. **Create a changeset** - Describe your changes and version bump type
2. **Commit & push** - Include the changeset with your code changes
3. **Merge "Version Packages" PR** - GitHub Action creates this automatically
4. **Package is published** - Happens automatically when the PR is merged

## Creating a Changeset

After making changes, create a changeset file:

```bash
# Using the CLI (interactive)
bunx changeset

# Or manually create a file in .changeset/
```

### Manual Changeset Format

Create a file in `.changeset/` with any name ending in `.md`:

```markdown
---
"@_mustachio/openauth": patch
---

Brief description of the changes.
```

### Version Bump Types

- **patch** - Bug fixes, documentation updates (0.0.X)
- **minor** - New features, backward-compatible changes (0.X.0)
- **major** - Breaking changes (X.0.0)

## GitHub Workflow

The release process is automated via `.github/workflows/release.yml`:

1. **On push to `master`**: The `changesets/action` runs
2. **If changesets exist**: Creates/updates a "Version Packages" PR that:
   - Consumes (deletes) changeset files
   - Bumps version in `package.json`
   - Updates `CHANGELOG.md`
3. **When PR is merged**: Publishes to npm with provenance

## Example Workflow

```bash
# 1. Make your changes
git checkout -b my-feature

# 2. Create a changeset
cat > .changeset/my-feature.md << 'EOF'
---
"@_mustachio/openauth": minor
---

Add new authentication provider for XYZ.
EOF

# 3. Commit and push
git add .
git commit -m "feat: add XYZ provider"
git push origin my-feature

# 4. Create PR and merge to master

# 5. GitHub Action creates "Version Packages" PR

# 6. Merge that PR to publish
```

## Resolving Conflicts

If the "Version Packages" PR has conflicts (usually with `.changeset/` files):

```bash
git fetch origin
git checkout changeset-release/master
git pull origin changeset-release/master
git merge master

# If conflict is a changeset file that was consumed, delete it:
git rm .changeset/conflicting-file.md
git commit -m "merge: resolve conflict by removing consumed changeset"
git push origin changeset-release/master
```

## Local Testing

Before creating a release, ensure tests pass:

```bash
cd packages/openauth
bun test
```
