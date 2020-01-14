
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

spec:
	$(MAKE) -C $(REPO_HOME)/doc/ spec


tests-assembler:
	$(MAKE) -C $(REPO_HOME)/tests/assembler all

tests-compiler:
	$(MAKE) -C $(REPO_HOME)/tests/compiler  all

tests-kat:
	$(MAKE) -C $(REPO_HOME)/tests/kat       all

tests-all: tests-assembler tests-compiler tests-kat

opcodes:
	cat $(REPO_HOME)/extern/riscv-opcodes/opcodes \
        $(REPO_HOME)/tools/opcodes-crypto \
	| python3 $(REPO_HOME)/bin/parse_opcodes.py -c > build/opcodes-all.h
	cat $(REPO_HOME)/tools/opcodes-crypto \
	| python3 $(REPO_HOME)/bin/parse_opcodes.py -c > build/opcodes-crypto.h


clean:
	$(MAKE) -C $(REPO_HOME)/doc/ clean
	$(MAKE) -C $(REPO_HOME)/benchmarks/hash/sha3 clean

