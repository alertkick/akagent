#!/bin/bash
set -e

# Release workflow: develop → main (via PR) → tag

# Ensure we're on develop
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "develop" ]; then
    echo "ERROR: Must be on 'develop' branch. Currently on '${CURRENT_BRANCH}'"
    exit 1
fi

# Ensure working directory is clean
if ! git diff-index --quiet HEAD --; then
    echo "ERROR: Working directory is not clean. Commit or stash changes first."
    exit 1
fi

# Ensure develop is up to date with remote
git fetch origin
LOCAL=$(git rev-parse develop)
REMOTE=$(git rev-parse origin/develop)
if [ "$LOCAL" != "$REMOTE" ]; then
    echo "ERROR: Local develop is not in sync with origin. Push or pull first."
    exit 1
fi

# Ensure there are commits to release
COMMIT_COUNT=$(git rev-list --count origin/main..develop)
if [ "$COMMIT_COUNT" -eq 0 ]; then
    echo "ERROR: No new commits on develop since last release. Nothing to release."
    exit 1
fi

# Calculate next version (sort tags by semver to get the actual latest)
version=$(git tag -l 'v*' --sort=-version:refname | head -1)
if [ -z "$version" ]; then
    version="v0.0.0"
    echo "No existing tags found, starting from: $version"
else
    echo "Current version: $version"
fi

version_num=${version#v}
A=$(echo $version_num | cut -d '.' -f1)
B=$(echo $version_num | cut -d '.' -f2)
C=$(echo $version_num | cut -d '.' -f3)

# Compute candidate patch (with rollover at .9) and minor versions.
patch_A=$A; patch_B=$B; patch_C=$C
if [ $patch_C -gt 8 ]; then
    if [ $patch_B -gt 8 ]; then
        patch_A=$((patch_A+1)); patch_B=0; patch_C=0
    else
        patch_B=$((patch_B+1)); patch_C=0
    fi
else
    patch_C=$((patch_C+1))
fi
patchVersion="v$patch_A.$patch_B.$patch_C"

minor_A=$A; minor_B=$((B+1)); minor_C=0
if [ $minor_B -gt 9 ]; then
    minor_A=$((minor_A+1)); minor_B=0
fi
minorVersion="v$minor_A.$minor_B.$minor_C"

# Show what will be released
echo ""
echo "Commits to be released (develop → main):"
git log --oneline origin/main..develop | head -20
echo ""
echo "Candidates:"
echo "  patch  → ${patchVersion}  (default — backwards-compatible)"
echo "  minor  → ${minorVersion}  (pick this if this release contains breaking changes)"
echo ""

read -p "Are there any breaking changes in this release? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    nextVersion=$minorVersion
    relType="minor (breaking)"
else
    nextVersion=$patchVersion
    relType="patch"
fi

echo "New version will be: ${nextVersion} (${relType})"
echo ""

read -p "Create PR to merge develop → main and tag ${nextVersion}? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Release cancelled"
    exit 1
fi

# Build default PR body and squash message
COMMIT_LOG=$(git log --oneline origin/main..develop | sed 's/^/- /')
DEFAULT_BODY="## Release ${nextVersion}

### Changes since ${version}
${COMMIT_LOG}"

# Write to temp file for editing
TMPFILE=$(mktemp /tmp/release-msg-XXXXXX.md)
echo "$DEFAULT_BODY" > "$TMPFILE"

# Open editor for the user to customize
echo "Opening editor to customize the release/squash message..."
${EDITOR:-vi} "$TMPFILE"

# Read back the edited message
RELEASE_BODY=$(cat "$TMPFILE")
rm -f "$TMPFILE"

if [ -z "$RELEASE_BODY" ]; then
    echo "ERROR: Release message is empty. Aborting."
    exit 1
fi

# Create PR from develop → main
echo "Creating PR..."
PR_URL=$(gh pr create \
    --base main \
    --head develop \
    --title "Release ${nextVersion}" \
    --body "$RELEASE_BODY")
echo "PR created: ${PR_URL}"

read -p "Squash-merge the PR and tag ${nextVersion}? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "PR created but not merged. Merge manually when ready, then tag main."
    exit 0
fi

# Squash-merge the PR with the edited message as commit message
echo "Squash-merging PR..."
gh pr merge --squash --subject "Release ${nextVersion}" --body "$RELEASE_BODY" --delete-branch=false

# Pull latest main and tag it
git checkout main
git pull origin main
git tag -a $nextVersion -m "Release $nextVersion"
git push --tags

# Reset develop to main so they're in sync after squash merge
git checkout develop
git reset --hard origin/main
git push --force-with-lease origin develop

echo ""
echo "Release ${nextVersion} complete!"
echo "  - PR merged: ${PR_URL}"
echo "  - Tag ${nextVersion} pushed to main"
echo "  - develop branch reset to main"
echo "  - Jenkins will build and upload the release"
