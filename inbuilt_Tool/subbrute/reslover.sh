#!/bin/bash

# Usage: ./filter_fast_resolvers_fast.sh <target_domain_or_ip>
# Output: fast_resolvers.txt with only responsive DNS resolvers
# Speed optimized using parallel subshells

target=$1
max_jobs=50  # Number of concurrent resolver tests

if [ -z "$target" ]; then
  echo "[!] Usage: $0 <target_domain_or_ip>"
  exit 1
fi

echo "[*] Testing resolvers against: $target"
> fast_resolvers.txt  # clear output file

# Job control function
job_control() {
  while [ "$(jobs -rp | wc -l)" -ge "$max_jobs" ]; do
    sleep 0.1
  done
}

while read -r ip; do
  job_control
  {
    if dig @"$ip" "$target" +timeout=1 +short | grep -q '\.'; then
      echo "$ip [OK]"
      echo "$ip" >> fast_resolvers.txt
    else
      echo "$ip [FAIL]"
    fi
  } &
done < resolvers.txt

# Wait for all jobs to finish
wait
echo "[+] Fast resolvers saved to: fast_resolvers.txt"
