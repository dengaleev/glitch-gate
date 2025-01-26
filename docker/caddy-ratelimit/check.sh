#!/bin/bash

# Define the URLs to query
urls=("localhost:8080" "localhost:8081")

# Loop through the URLs 10 times
for i in {1..10}; do
  for url in "${urls[@]}"; do
    # Run curl with the desired write-out format
    curl -o /dev/null -s -w "Request $i | URL: $url | HTTP Status: %{http_code} | Retry-After: %header{retry-after} | Duration: %{time_total}s | Time: $(date)\n" $url
  done
  sleep 1
done
