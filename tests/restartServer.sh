#!/bin/bash

for i in {1..20}; do logCollector -s -a 0.0.0.0:3000& sleep $((($i % 10)*3 + 10)); kill %1; sleep 15; done
