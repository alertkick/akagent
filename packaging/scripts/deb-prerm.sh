#!/bin/sh
case "$1" in
    remove)
        # Stop the agent if we are removing
        service alertpriority-agent stop || :
        ;;
    upgrade)
        :
        ;;
    purge)
        :
        ;;
    *)
        echo "Unrecognized prerm argument '$1'"
        ;;
esac
