#!/bin/sh
make clean


for h in 0 1 2
do
	CFLAGS="-DH=$h  -DFAST=0" python3 benchmarks.py #>/dev/null 2>&1
	CFLAGS="-DH=$h  -DFAST=0 -DNO_BITMASK" python3 benchmarks.py #>/dev/null 2>&1
	CFLAGS="-DH=$h  -DFAST=0 -DPRE_COMP" python3 benchmarks.py #>/dev/null 2>&1
	CFLAGS="-DH=$h  -DFAST=0 -DNO_BITMASK -DPRE_COMP" python3 benchmarks.py #>/dev/null 2>&1
	echo "Benchmark completed!\n--- -DH=$h"
done

for b in 0 1 2
do
	for s in 8 9 10 11 12 13 14 15
	do
		for h in 0 1 2
		do
			CFLAGS="-DH=$h -DFAST=1 -DBLOCK=$b -DSHIFT=${s}" python3 benchmarks.py #>/dev/null 2>&1
			CFLAGS="-DH=$h  -DFAST=1 -DNO_BITMASK -DBLOCK=$b -DSHIFT=${s}" python3 benchmarks.py #>/dev/null 2>&1
			CFLAGS="-DH=$h  -DFAST=1 -DPRE_COMP -DBLOCK=$b -DSHIFT=${s}" python3 benchmarks.py #>/dev/null 2>&1
			CFLAGS="-DH=$h  -DFAST=1 -DNO_BITMASK -DPRE_COMP -DBLOCK=$b -DSHIFT=${s}" python3 benchmarks.py #>/dev/null 2>&1
			echo "Benchmark completed!\n---"
		done
	done
done