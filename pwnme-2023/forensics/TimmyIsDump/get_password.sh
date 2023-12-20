#!/bin/bash

function zipZeFile() {
    password=$(echo "$1" | cut -c 1-15)
    echo $password
}

function Generate-Password() {
    shaSum=$(dd if=/dev/random bs=32 count=1 2>/dev/null | sha256sum | cut -d " " -f 1)
    aesIV=$(echo -n "$shaSum" | base64 | head -c 16)
    easKey=$(echo -n "$shaSum" | sha256sum | cut -d " " -f 1)
    encrypted=$(echo -n "hello world" | openssl enc -aes-256-cbc -K "$easKey" -iv "0123456789012345" -base64)
    key=$(echo -n "$password" | sha512sum | cut -d " " -f 1)
    zipZeFile "$key"
}

Generate-Password