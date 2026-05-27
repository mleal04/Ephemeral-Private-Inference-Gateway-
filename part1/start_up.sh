#!/bin/bash

# Updated to include your helper file and match your executable name
SOURCE_FILES="gateway_server.c gateway_server_helper.c worker_process.c"
EXECUTABLE="gateway_server"

# Remove old executables and exit  
if [ "$1" == "clean" ]; then
    echo "Cleaning up..."
    rm -f $EXECUTABLE
    echo "Folder is clean."
    exit 0
fi

# Begin checks and compile
echo "Performing File Checks..."

for FILE in $SOURCE_FILES; do
    if [ -x "$FILE" ]; then
        echo "Warning: $FILE is marked as executable. That's weird for source code!"
        echo "Fixing permissions for $FILE..."
        chmod -x "$FILE"
    fi
done

echo "Compiling Gateway Server with OpenSSL paths..."

# Compile everything and link with OpenSSL pathing for Mac/Homebrew
gcc $SOURCE_FILES -o $EXECUTABLE \
    -I/opt/homebrew/opt/openssl@3/include \
    -L/opt/homebrew/opt/openssl@3/lib \
    -lssl -lcrypto

# Check if the compiler succeeded
if [ $? -eq 0 ]; then
    echo "Build Successful!"

    # Ensure the RESULT is executable
    if [ ! -x "$EXECUTABLE" ]; then
        chmod +x "$EXECUTABLE"
    fi

    # IF no argument is given, default to 127.0.0.1 (localhost)
    IP_ADDRESS="${1:-127.0.0.1}"

    echo "Launching Gateway Server on $IP_ADDRESS..."
    ./$EXECUTABLE "$IP_ADDRESS"
else
    echo "Build Failed! Check your C syntax."
fi