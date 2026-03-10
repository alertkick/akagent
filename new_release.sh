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

# Calculate next version
version=$(git describe --tags $(git rev-list --tags --max-count=1) 2>/dev/null)
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

if [ $C -gt 8 ]; then
    if [ $B -gt 8 ]; then
        A=$((A+1))
        B=0
        C=0
    else
        B=$((B+1))
        C=0
    fi
else
    C=$((C+1))
fi

nextVersion="v$A.$B.$C"

# Show what will be released
echo ""
echo "Commits to be released (develop → main):"
git log --oneline origin/main..develop | head -20
echo ""
echo "New version will be: ${nextVersion}"
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
git checkout develop

echo ""
echo "Release ${nextVersion} complete!"
echo "  - PR merged: ${PR_URL}"
echo "  - Tag ${nextVersion} pushed to main"
echo "  - Jenkins will build and upload the release"
