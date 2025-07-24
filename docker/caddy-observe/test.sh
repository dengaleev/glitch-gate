#!/bin/bash

curl http://localhost:8080 -H 'X-Token: 12345'


# for i in {1..100000}; do
#     curl -s -o /dev/null http://localhost:8080 &
#     if (( i % 1000 == 0 )); then
#         wait
#     fi
# done

