#! /bin/bash

# this file takes one argument, bump as -b
#  if -b is not provided, it will bump the version otherwise we just return the latest tag.

if [ "$1" == "-b" ]; then
    bump=true
else
    bump=false
fi

if [ "$bump" == false ]; then
    version=$(git describe --tags `git rev-list --tags --max-count=1`)
    echo "$version"
else
    version=$(git describe --tags `git rev-list --tags --max-count=1`)
    echo "Current version: $version"

    #Version to get the latest tag 
    A=$(echo $version|cut -d '.' -f1)
    B=$(echo $version|cut -d '.' -f2)
    C=$(echo $version|cut -d '.' -f3)
    if [ $C -gt 8 ]; then
        if [ $B -gt 8 ]; then
            A=$((A+1))
            B=0 C=0 
        else
            B=$((B+1))
            C=0
        fi
    else
        C=$((C+1))
    fi
    nextVersion="$A.$B.$C"
    echo "New version will be '${nextVersion}'"

    git tag -a $nextVersion -m "Release $nextVersion"
    git push --tags

    echo "New version '${nextVersion}' released"
fi
