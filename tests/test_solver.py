import sys
import os
sys.path.append(os.getcwd() + "/../");

import crypto
from crypto import digest
from utils import puzzles
from os import urandom
from time import time



for difficulty in range(1, 30):
	for iteration in range(0, 10):
		irandom = urandom(16)
		ihit=urandom(16)
		rhit=urandom(16)
		rhash=digest.SHA256Digest()
		start = time();
		jrandom = puzzles.PuzzleSolver.solve_puzzle(irandom, rhit, ihit, difficulty, rhash)
		#print(puzzles.PuzzleSolver.verify_puzzle(irandom, jrandom, rhit, ihit, difficulty, rhash))
		end = time();
		print(difficulty, iteration, end - start);