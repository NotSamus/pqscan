#!/bin/bash

# Name of your Python file
PYTHON_SCRIPT="scanner.py"

# Optional: specify Python interpreter (uncomment if needed)
# PYTHON_BIN="/usr/bin/python3"

for i in {1..100}
do
    echo "Run #$i"
    python3 "$PYTHON_SCRIPT"
    # or use "$PYTHON_BIN" "$PYTHON_SCRIPT" if you defined it above
done

echo "All 100 runs completed."
