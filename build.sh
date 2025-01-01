#!/bin/bash

#
# SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
#

# Output file
output_file="spam-filter.toml"

echo -e "[version]\nspam-filter = \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"\nserver = \"$(cat MIN_SERVER_SEMVER)\"\n" > "$output_file"

if [ -d "rules" ]; then
    for file in rules/*.toml; do
        if [ -f "$file" ]; then
            cat "$file" >> "$output_file"
            echo -e "\n" >> "$output_file"
        fi
    done
fi

if [ -d "lists" ]; then
    echo "# Lists" >> "$output_file"
    for file in lists/*.toml; do
        if [ -f "$file" ]; then
            cat "$file" >> "$output_file"
            echo -e "\n" >> "$output_file"
        fi
    done
fi

echo "Combined TOML files into $output_file"
