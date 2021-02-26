
SAIL_REPO=$(REPO_HOME)/extern/sail-riscv

sail-build-rv32-csim: sail-update-model
	$(MAKE) -C $(SAIL_REPO) csim ARCH=RV32

sail-build-rv64-csim: sail-update-model
	$(MAKE) -C $(SAIL_REPO) csim ARCH=RV64

sail-build-rv32-osim: sail-update-model
	$(MAKE) -C $(SAIL_REPO) osim ARCH=RV32

sail-build-rv64-osim: sail-update-model
	$(MAKE) -C $(SAIL_REPO) osim ARCH=RV64

sail-build-all : sail-build-rv32-csim \
                 sail-build-rv64-csim \
                 sail-build-rv32-osim \
                 sail-build-rv64-osim

