
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

spec:
	$(MAKE) -C $(REPO_HOME)/doc/ spec


tests-assembler:
	$(MAKE) -C $(REPO_HOME)/tests/assembler all

tests-compiler:
	$(MAKE) -C $(REPO_HOME)/tests/compiler all

tests-all: tests-assembler tests-compiler


benchmarks:
	$(MAKE) -C $(REPO_HOME)/benchmarks/hash/sha3 all


clean:
	$(MAKE) -C $(REPO_HOME)/doc/ clean
	$(MAKE) -C $(REPO_HOME)/benchmarks/hash/sha3 clean

