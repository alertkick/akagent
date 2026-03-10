#!/bin/bash

# Get the latest tag
version=$(git describe --tags $(git rev-list --tags --max-count=1) 2>/dev/null)

# If no tags exist, start with version 0.0.0
if [ -z "$version" ]; then
    version="0.0.0"
    echo "No existing tags found, starting with version: $version"
else
    echo "Current version: $version"
fi

# Parse version components
A=$(echo $version | cut -d '.' -f1)
B=$(echo $version | cut -d '.' -f2)
C=$(echo $version | cut -d '.' -f3)

# Increment version logic
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

nextVersion="$A.$B.$C"
echo "New version will be '${nextVersion}'"

# Confirm before creating tag
read -p "Do you want to create and push tag '${nextVersion}'? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Create and push the tag
    git tag -a $nextVersion -m "Release $nextVersion"
    git push --tags

    echo "New version '${nextVersion}' released successfully!"
    echo "Tag created and pushed to remote repository"

    # Show recent commits for release notes
    echo ""
    echo "Recent commits since last tag:"
    git log --oneline --since="$(git log -1 --format=%ai $version 2>/dev/null || echo '1 week ago')" --pretty=format:"  %h %s" | head -10
else
    echo "Release cancelled"
    exit 1
fi
