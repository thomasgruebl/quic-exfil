#!/bin/bash

export PATH=$PATH
export HOME=$HOME

echo "Starting benign connn migr script..."
while true; do
	DELAY=$((RANDOM % 1801))
	sleep "$DELAY"
	echo "Triggering benign conn migr..."
	../quiche/target/release/quiche-client https://192.168.100.63:4433/index.html --no-verify --enable-active-migration --perform-migration
done
