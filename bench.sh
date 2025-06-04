
#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
 
# Check if at least one argument is provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <application> [args...]"
    exit 1
fi
 
# Variables
APP="$1"  # The application to run
shift      # Remove the application from the arguments list
ARGS="$@"  # Remaining arguments passed to the application
USER="rrudnick"  # The user to own the generated perf data
FLAMEGRAPH_DIR="./FlameGraph"  # Path to the FlameGraph repository
 
# Check if FlameGraph repository exists
if [ ! -d "$FLAMEGRAPH_DIR" ]; then
    echo "Error: FlameGraph directory not found at $FLAMEGRAPH_DIR."
    echo "Clone it using: git clone https://github.com/brendangregg/FlameGraph.git"
    exit 1
fi
 
# Run application under perf
echo "Recording performance data..."
sudo perf record -F 99 -g --call-graph dwarf -- "$APP" $ARGS
 
# Change ownership of the generated perf data
echo "Changing ownership of perf data..."
sudo chown "$USER" perf.data
 
# Process perf.data into a readable format
echo "Processing perf data..."
perf script > out.perf
 
# Generate folded stacks
echo "Generating folded stacks..."
"$FLAMEGRAPH_DIR/stackcollapse-perf.pl" out.perf > out.folded
 
# Generate the flame graph
echo "Generating flame graph..."
"$FLAMEGRAPH_DIR/flamegraph.pl" out.folded > flamegraph.svg
 
# Open the flame graph in Firefox
echo "Opening flame graph in Firefox..."
firefox flamegraph.svg &
 
echo "Done! The flame graph is saved as flamegraph.svg."


