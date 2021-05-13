#!/usr/bin/env python3

'''
TODO:
	1.gen CG (ok)
		.bc file, tmp dir

	2.eliminate non-state block
		cfg

	3.merge CG & CFG
		1.specify callsite, replace eliminated node with state node
		2.
'''

import argparse
import subprocess
import sys
import collections
import functools
import networkx as nx
import multiprocessing as mp
from pathlib import Path
from argparse import ArgumentTypeError as ArgTypeErr
from concurrent.futures import ThreadPoolExecutor

STEP = 0 # step number
STATE_FN = "state-fast" # step file containing the step number
DOT_DIR = "dot-files"
CALLGRAPH = "callgraph.dot"
PROJ_ROOT = Path(__file__).resolve().parent.parent

class memoize:
  # From https://github.com/S2E/s2e-env/blob/master/s2e_env/utils/memoize.py

  def __init__(self, func):
    self._func = func
    self._cache = {}

  def __call__(self, *args):
    if not isinstance(args, collections.abc.Hashable):
      return self._func(args)

    if args in self._cache:
      return self._cache[args]

    value = self._func(*args)
    self._cache[args] = value
    return value

  def __repr__(self):
    # Return the function's docstring
    return self._func.__doc__

  def __get__(self, obj, objtype):
    # Support instance methods
    return functools.partial(self.__call__, obj)


#================================================================
# check if the path is a dir
def is_path_to_dir(path):
	""" Returns Path object when path is an existing directory """
	p = Path(path) # Path() from pathlib
	if not p.exists():
		raise ArgTypeErr("path dose not exist")
	if not p.is_dir():
		raise ArgTypeErr("not a directory")

	return p
#================================================================

#================================================================
def get_resume(args):
	fn = args.tmp_dir / STATE_FN
	r = 0
	try:
		with fn.open("r") as f:
			r = int(f.read())
	except FileNotFoundError:
		pass
	
	return r
#================================================================

#================================================================
def next_step(args):
	global STEP
	STEP += 1
	fn = args.tmp_dir / STATE_FN
	with fn.open("w") as f:
		print(STEP, file=f)
#================================================================

#================================================================
def abort(args):
	print(f"Failed in step {STEP}", file=sys.stderr)
	log_p = args.tmp_dir / f"step{STEP}.log"
	print(f"check {log_p} for more detail info", file=sys.stderr)
	sys.exit(1)
#================================================================

#================================================================
def remove_repeated_lines(in_path, out_path):
	lines_seen = set()
	with out_path.open("w") as out, in_path.open("r") as in_f:
		for line in in_f.readlines():
			if line not in lines_seen:
				out.write(line)
				lines_seen.add(line)
#================================================================


#================================================================
def merge_callgraphs(dots, outfilepath):
	import networkx as nx
	print(f"({STEP}) Integrating several callgraphs into one")
	
	G = nx.DiGraph()
	for dot in dots:
		G.update(nx.DiGraph(nx.drawing.nx_pydot.read_dot(dot)))
	with outfilepath.open('w') as f:
		nx.drawing.nx_pydot.write_dot(G, f)
#================================================================

#================================================================
# using opt to gen CG
def opt_callgraph(args, binary):
	print(f"({STEP}) Constructing CG for {binary}..")
	dot_files = args.tmp_dir / DOT_DIR
	cmd = ["opt-10", "-dot-callgraph", f"{binary}",
		   "-o", "/dev/null"]
	log_p = args.tmp_dir / f"step{STEP}.log"
	with log_p.open("w") as f:
		try:
			subprocess.run(cmd, stderr=f, check=True, cwd=dot_files)
		except subprocess.CalledProcessError:
			abort(args)
#================================================================

#================================================================
def construct_CG(args, binaries):
	fuzzer = args.fuzzer_name
	dot_files = args.tmp_dir / DOT_DIR
	callgraph_out = dot_files / CALLGRAPH

	if fuzzer:
		tmp = next(args.bin_dir.glob(f"{fuzzer.name}.0.0.*.bc"))
		binaries = [tmp]

	for binary in binaries:
		opt_callgraph(args, binary)
		callgraph = dot_files / f"{binary.name}.callgraph.dot"
		tmp = dot_files / f"{binary.name}.callgraph.tmp.dot"
		callgraph_out.replace(tmp)
		remove_repeated_lines(tmp, callgraph)
		tmp.unlink()
		
	# 
	if fuzzer:
		cg = dot_files / f"{binary.name}.callgraph.dot"
		cg.replace(callgraph_out)
	else:
		callgraphs = dot_files.glob("*.callgraph.dot")
		merge_callgraphs(callgraphs, callgraph_out)

	next_step(args) # step 0 -> 1
#================================================================

def node_name(name):
	return "\"{%s}\"" % name

@memoize
def find_nodes(name, G):
	n_name = node_name(name)
	return [n for n, d in G.nodes(data=True) if n_name in d.get('label', '')]


def simplify_CFG(args):
	dot_files = args.tmp_dir / DOT_DIR
	bbcalls = args.tmp_dir / "BBcalls.txt"
	callgraph = dot_files / CALLGRAPH
	
	# read callgraph dot file
	with callgraph.open("r") as f:
		callgraph_dot = f.read()

	# read bb callsite file
	with bbcalls.open("r+") as callf:
		lines = callf.readlines()
		callsites = {}
		for l in lines:
			s = l.strip().split(",")
			bb_name = node_name(s[0])
			if bb_name in callsites:
				callsites[bb_name].add(s[1])
			else:
				callsites[bb_name] = {s[1]}

	print("callsite: ", callsites)
		
	def simplify_CFG_from_file(cfg: Path):
		if cfg.stat().st_size == 0: return
		
		print("file name: " + cfg.name)
		name = cfg.name.split('.')[-2]

		# skip the function that never used
		if name not in callgraph_dot: return

		outname = "new_cfg." + name + ".dot"
		outpath = cfg.parent / outname

		out_callsite = cfg.parent.parent / "BBcalls.new.txt"

		print("parse cfg of %s .." % name)
		G = nx.DiGraph(nx.drawing.nx_pydot.read_dot(cfg))
		nodes = G.nodes(data=True)
		
		remove_list = []
		for n in nodes:
			if ('tran:' in n[1].get('label')) or ('check:' in n[1].get('label')):
				# print(n)
				pass
			else:
				# reserve in and out block
				# p = G.in_degree(n[0])
				# if not p: continue
				# c = G.out_degree(n[0])
				# if not c: continue
				remove_list.append(n)

		# add new edge from non-state node's pred to succ, and remove non-state node
		new_edges = []
		for n in remove_list:
			try:
				parent = G.pred[n[0]]
				child = G.succ[n[0]]
				for p in parent:
					for c in child:
						# Graph cannot be changed during iteration, 
						# so we have to save edge and then add.
						new_edges.append({p : c})
			except nx.NetworkXError as err:
				pass

			for pair in new_edges:
				for p, c in pair.items():
					G.add_edge(p, c)

		for n in remove_list:
			n_name = n[1].get('label', '')
			print(n_name)

			# replace callsite node with pred node
			if  n_name in callsites:
				parent = G.pred[n[0]]
				for p in parent:
					p_name = G.nodes[p].get('label')
					if p_name in callsites:
						callsites[p_name].union(callsites[n_name])
					else:
						callsites[p_name] = callsites[n_name]
				
				callsites.pop(n_name)

			G.remove_node(n[0])

		print("new callsite: ", callsites)
		with out_callsite.open("w") as out:
			for caller, callees in callsites.items():
				caller = caller[2:-2]
				for callee in callees:
					out.write(caller + "," + callee + "\n")

		print("write to %s" % outpath)
		nx.drawing.nx_pydot.write_dot(G, outpath)


	print(f"({STEP}) eliminate non-state block in each CFG")
	for file in dot_files.glob("cfg.*.dot"):
		simplify_CFG_from_file(file)
	'''
	with ThreadPoolExecutor(max_workers=mp.cpu_count()) as executor:
		results = executor.map(simplify_CFG_from_file, 
							   dot_files.glob("cfg.*.dot"))
	'''
#================================================================

def merge_CFG(args):
	dot_files = args.tmp_dir / DOT_DIR
	bbcalls = args.tmp_dir / "BBcalls.new.txt"
	cfgs = dot_files.glob("new_cfg.*.dot")

	outpath = dot_files / "controlflowgraph.dot"
	G = nx.DiGraph()

	in_nodes = {}
	out_nodes = {}
	for cfg in cfgs:
		tmp_in = []
		tmp_out = []
		F = nx.DiGraph(nx.drawing.nx_pydot.read_dot(cfg))
		f_name = cfg.name.split('.')[-2]
		print("fname:", f_name)
		nodes = F.nodes(data=True)
		for n in nodes:
			if F.in_degree(n[0]) == 0:
				tmp_in.append(n[0])
			if F.out_degree(n[0]) == 0:
				tmp_out.append(n[0])

		in_nodes[f_name] = tmp_in
		out_nodes[f_name] = tmp_out
		G.update(F)

	nodes = G.nodes(data=True)
	new_edges = []
	with bbcalls.open("r") as callf:
		lines = callf.readlines()
		for l in lines:
			s = l.split(",")
			caller = s[0]
			callee = s[1].strip()
			# print(caller, callee)
			for n in nodes:
				if caller in n[1].get('label'):
					if callee not in in_nodes: continue
					for x in in_nodes[callee]:
						print(n[0], x)
						new_edges.append((n[0], x))
					
					child = G.succ[n[0]]
					for c in child:
						for x in out_nodes[callee]:
							new_edges.append((x, c))

	G.add_edges_from(new_edges)
	
	print("write final cfg %s" % outpath)
	nx.drawing.nx_pydot.write_dot(G, outpath)

#================================================================
def main():
	global STEP
	# parse args
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("bin_dir", metavar="binaries-directory",
						type=is_path_to_dir,
						help="Directory where binaries of 'subject' are located")
	parser.add_argument("tmp_dir", metavar="temporary-directory",
						type=is_path_to_dir,
						help="Directory where dot files and target files are located")
	parser.add_argument("fuzzer_name", metavar="fuzzer-name",
						nargs='?',
						help="Name of fuzzer binary")
	args = parser.parse_args()

	# sanity check
	binaries = list(args.bin_dir.glob("*.0.0.*bc"))
	if len(binaries) == 0:
		parser.error("Couldn't find any binaries in folder "
					f"{args.bin_dir}.")

	if args.fuzzer_name:
		tmp = args.bin_dir.glob(f"{args.fuzzer_name}.0.0.*.bc")
		args.fuzzer_name = args.bin_dir / args.fuzzer_name
		if not args.fuzzer_name.exists() or args.fuzzer_name.is_dir():
			parser.error(f"Could not find {args.fuzzer_name}.")
		if len(list(tmp)) == 0:
			parser.error(f"Could not find fuzzer {args.fuzzer_name} in folder {args.bin_dir}.")

	STEP = get_resume(args)
	# gen CG
	if not STEP:
		construct_CG(args, binaries)

	# simplify CFG
	simplify_CFG(args)

	# merge CG & CFGs
	merge_CFG(args)


if __name__ == '__main__':
	main()
