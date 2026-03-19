#!/bin/bash

SOURCE_FILES="gateway_server.c worker_process.c"
EXECUTABLE="gateway"

#remove old executables and exit  
if [ "$1" == "clean" ]; then
    echo "Cleaning up..."
    rm -f $EXECUTABLE
    echo "Folder is clean."
    exit 0
fi

#begin checks and compile
echo "Performing File Checks"

for FILE in $SOURCE_FILES; do
    if [ -x "$FILE" ]; then
        echo "Warning: $FILE is marked as executable. That's weird for source code!"
        echo "Fixing permissions for $FILE..."
        chmod -x "$FILE"
    fi
done

echo "Compiling PCC Node"

# Compile everything and link with OpenSSL
gcc $SOURCE_FILES -o $EXECUTABLE \
    -I/opt/homebrew/opt/openssl@3/include \
    -L/opt/homebrew/opt/openssl@3/lib \
    -lssl -lcrypto

# Check if the compiler succeeded
if [ $? -eq 0 ]; then
    echo "Build Successful!"

    # Ensure the RESULT is executable (the only one that should be)
    if [ ! -x "$EXECUTABLE" ]; then
        chmod +x "$EXECUTABLE"
    fi

    echo "Launching Gateway Server..."
    ./$EXECUTABLE "$1"
else
    echo "Build Failed! Check your C syntax."
fi