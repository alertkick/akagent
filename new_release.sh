#!/bin/bash
set -e

# Release workflow: develop → main (squash PR) → tag.
#
# Usage: ./new_release.sh [patch|minor]
#   patch  bump the last version component, rolling .8 → next minor (default)
#   minor  bump the second component (reset patch); use for breaking changes
#
# Runs non-interactively: the bump type is the only input, passed as the first
# argument. Always prefer this over `git tag -a v…` directly so the rollover
# logic stays consistent.

RELEASE_TYPE="${1:-patch}"
case "$RELEASE_TYPE" in
    patch|minor) ;;
    *)
        echo "Usage: $0 [patch|minor]"
        echo "  patch  bump the last version component (default, backwards-compatible)"
        echo "  minor  bump the second component (breaking changes)"
        exit 1
        ;;
esac

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
A=$(echo "$version_num" | cut -d '.' -f1)
B=$(echo "$version_num" | cut -d '.' -f2)
C=$(echo "$version_num" | cut -d '.' -f3)

# Compute candidate patch (with rollover at .8) and minor versions.
patch_A=$A; patch_B=$B; patch_C=$C
if [ "$patch_C" -gt 8 ]; then
    if [ "$patch_B" -gt 8 ]; then
        patch_A=$((patch_A+1)); patch_B=0; patch_C=0
    else
        patch_B=$((patch_B+1)); patch_C=0
    fi
else
    patch_C=$((patch_C+1))
fi
patchVersion="v$patch_A.$patch_B.$patch_C"

minor_A=$A; minor_B=$((B+1)); minor_C=0
if [ "$minor_B" -gt 9 ]; then
    minor_A=$((minor_A+1)); minor_B=0
fi
minorVersion="v$minor_A.$minor_B.$minor_C"

if [ "$RELEASE_TYPE" = "minor" ]; then
    nextVersion=$minorVersion
    relType="minor (breaking)"
else
    nextVersion=$patchVersion
    relType="patch"
fi

echo ""
echo "Commits to be released (develop → main):"
git log --oneline origin/main..develop | head -20
echo ""
echo "New version will be: ${nextVersion} (${relType})"
echo ""

# Build the PR body / squash commit message from the commit log.
COMMIT_LOG=$(git log --oneline origin/main..develop | sed 's/^/- /')
RELEASE_BODY="## Release ${nextVersion}

### Changes since ${version}
${COMMIT_LOG}"

# Create PR from develop → main
echo "Creating PR..."
PR_URL=$(gh pr create \
    --base main \
    --head develop \
    --title "Release ${nextVersion}" \
    --body "$RELEASE_BODY")
echo "PR created: ${PR_URL}"

# Squash-merge the PR with the release message as the commit message
echo "Squash-merging PR..."
gh pr merge --squash --subject "Release ${nextVersion}" --body "$RELEASE_BODY" --delete-branch=false

# Pull latest main and tag it
git checkout main
git pull origin main
git tag -a "$nextVersion" -m "Release $nextVersion"
git push --tags

# Reset develop to main so they're in sync after the squash merge
git checkout develop
git reset --hard origin/main
git push --force-with-lease origin develop

echo ""
echo "Release ${nextVersion} complete!"
echo "  - PR merged: ${PR_URL}"
echo "  - Tag ${nextVersion} pushed to main"
echo "  - develop branch reset to main"
echo "  - Jenkins will build and deploy on the tag webhook."
