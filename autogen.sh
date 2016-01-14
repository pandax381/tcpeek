#!/bin/bash

set -e

echo -n "checking for autoreconf... "
which autoreconf || {
    echo "*** No autoreconf found, please install it ***"
    exit 1
}

echo "running autoreconf --force --install --verbose"
autoreconf --force --install --verbose || exit $?

exit 0
