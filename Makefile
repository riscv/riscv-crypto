
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

specs:
	$(MAKE) -C $(REPO_HOME)/doc/ specs


OPCODES_SPEC_SCALAR = $(REPO_HOME)/tools/opcodes-crypto-scalar
OPCODES_SPEC_VECTOR = $(REPO_HOME)/tools/opcodes-crypto-vector

opcodes:
	cat $(REPO_HOME)/extern/riscv-opcodes/opcodes \
        $(OPCODES_SPEC_SCALAR) $(OPCODES_SPEC_VECTOR) \
	| python3 $(REPO_HOME)/bin/parse_opcodes.py -check
	cat $(OPCODES_SPEC_SCALAR) \
	| python3 $(REPO_HOME)/bin/parse_opcodes.py -c > build/opcodes-crypto_scalar.h
	cat $(OPCODES_SPEC_VECTOR) \
	| python3 $(REPO_HOME)/bin/parse_opcodes.py -c > build/opcodes-crypto_vector.h
	cat $(OPCODES_SPEC_SCALAR) \
	| python3 $(REPO_HOME)/bin/parse_opcodes.py -sail-boilerplate > build/opcodes-crypto_scalar.sail
	cat $(OPCODES_SPEC_VECTOR) \
	| python3 $(REPO_HOME)/bin/parse_opcodes.py -sail-boilerplate > build/opcodes-crypto_vector.sail


clean:
	$(MAKE) -C $(REPO_HOME)/doc/ clean
	$(MAKE) -C $(REPO_HOME)/benchmarks/hash/sha3 clean

doxygen:
	doxygen benchmarks/doxygen.conf

