
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

specs:
	$(MAKE) -C $(REPO_HOME)/doc/ specs


OPCODES_SPEC_SCALAR = $(REPO_HOME)/extern/riscv-opcodes/opcodes-rvk   \
                      $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32k \
                      $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64k
OPCODES_SPEC_VECTOR = $(REPO_HOME)/tools/opcodes-crypto-vector

PARSEOPCODES = python3 $(REPO_HOME)/bin/better_parse_opcodes.py

opcodes:
	$(PARSEOPCODES) verilog  $(OPCODES_SPEC_SCALAR) > build/decode_scalar.v
	$(PARSEOPCODES) verilog  $(OPCODES_SPEC_VECTOR) > build/decode_vector.v
	$(PARSEOPCODES) spike    $(OPCODES_SPEC_SCALAR) > build/spike_scalar.h
	$(PARSEOPCODES) spike    $(OPCODES_SPEC_VECTOR) > build/spike_vector.h
	$(PARSEOPCODES) binutils $(OPCODES_SPEC_SCALAR) > build/binutils_scalar.h
	$(PARSEOPCODES) binutils $(OPCODES_SPEC_VECTOR) > build/binutils_vector.h
	$(PARSEOPCODES) normal-parse-opcodes $(OPCODES_SPEC_SCALAR) > build/opcodes_scalar
	$(PARSEOPCODES) normal-parse-opcodes $(OPCODES_SPEC_VECTOR) > build/opcodes_vector
	$(PARSEOPCODES) sail $(OPCODES_SPEC_SCALAR) > build/scalar.sail
	$(PARSEOPCODES) wavedrom $(OPCODES_SPEC_SCALAR) > build/opcodes.json
	#$(PARSEOPCODES) sail $(OPCODES_SPEC_VECTOR) > build/vector.sail

clean:
	$(MAKE) -C $(REPO_HOME)/doc/ clean
	$(MAKE) -C $(REPO_HOME)/benchmarks/hash/sha3 clean

doxygen:
	doxygen benchmarks/doxygen.conf

