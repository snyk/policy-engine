#!/usr/bin/env bash
set -o nounset -o errexit -o pipefail

function generate_provider_schema {
    if [[ ! -d "$1" ]]; then
        git clone --depth 1 --single-branch --branch "$3" "$2" "$1"
    fi

    cp extract.go "$1"
    sed 's/^package .*$/package main/' ../../schemas.go >"$1"/schemas.go
    cp "main_$1".go "$1"/main.go

    cd "$1" && go run .
}

generate_provider_schema "aws" \
    "https://github.com/hashicorp/terraform-provider-aws" "v4.34.0" | \
    gzip >../aws.json.gz

generate_provider_schema "google" \
    "https://github.com/hashicorp/terraform-provider-google" "v4.40.0" | \
    gzip >../google.json.gz

generate_provider_schema "azurerm" \
    "https://github.com/hashicorp/terraform-provider-azurerm" "v3.26.0" | \
    gzip >../azurerm.json.gz
