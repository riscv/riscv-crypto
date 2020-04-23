
BUILD_DIR = $(REPO_BUILD)/rtl
YOSYS     = $(YOSYS_ROOT)/yosys

SYNTH_TARGETS   =
LINT_TARGETS    =
SIM_TARGETS     =
TARGETS         =
PROVE_TARGETS   =

define map_build_dir
$(BUILD_DIR)/${1}
endef

define map_synth_verilog
$(call map_build_dir,${1})/${1}.synth.v
endef

define map_cmos_verilog
$(call map_build_dir,${1})/${1}.cmos.v
endef

define map_synth_rpt
$(call map_build_dir,${1})/${1}.rpt
endef

define map_lint_rpt
$(call map_build_dir,${1})/${1}.lint
endef

define map_waves
$(call map_build_dir,${1})/${1}.vcd
endef

define map_sim_exe
$(call map_build_dir,${1})/${1}.sim
endef

define map_sim_log
$(call map_build_dir,${1})/${1}.simlog
endef

define map_sby_file
$(call map_build_dir,${1})/${1}.sby
endef

#
# 1. Name
# 2. SBY file
# 3. RTL/TB source files
define add_prove_target

${1} : ${3}
	mkdir -p $(dir $(call map_sby_file,${1}))
	cp ${2} $(call map_sby_file,${1})
	sby -f  $(call map_sby_file,${1})

PROVE_TARGETS += ${1}

endef

#
# 1. Target Name
# 2. Source Files
# 3. Top Module
define add_synth_target

$(call map_synth_rpt,${1}) : ${2}
	@mkdir -p $(call map_build_dir,${1})
	$(YOSYS) -qQT \
        -p "read_verilog ${2}" \
        -p "proc" \
        -p "synth -top ${3} -flatten" \
        -p "abc -g cmos" \
        -p "opt fast" \
        -p "write_verilog $(call map_cmos_verilog,${1})" \
        -p "flatten" \
        -p "tee -o $(call map_synth_rpt,${1}) stat -tech cmos" \
        -p "tee -a $(call map_synth_rpt,${1}) ltp -noff" \

synth-${1} : $(call map_synth_rpt,${1}) $(call map_lint_rpt,${1})

$(call map_lint_rpt,${1}) : ${2}
	@mkdir -p $(dir $(call map_lint_rpt,${1}))
	@rm -f $${@}
	verilator --top-module ${3} --lint-only $${^} | tee $${@}

lint-${1} : $(call map_lint_rpt,${1})

TARGETS += synth-${1}  lint-${1}
SYNTH_TARGETS += synth-${1}
LINT_TARGETS +=  lint-${1}
endef

#
# 1. Target Name
# 2. Source Files
define add_sim_target

$(call map_sim_exe,${1}) : ${2}
	mkdir -p $(dir $(call map_sim_exe,${1}))
	iverilog -DWAVEFILE=$(call map_waves,${1}) \
        -s${1}_tb -g2012 -o$${@} $${^}

$(call map_waves,${1})   : $(call map_sim_log,${1})
$(call map_sim_log,${1}) : $(call map_sim_exe,${1})
	vvp $${^}

sim-${1} : $(call map_waves,${1})

SIM_TARGETS += sim-${1}

TARGETS += $(call map_sim_log,${1})
TARGETS += $(call map_waves,${1})

endef

#
# Import sub-makefiles
#

include lut4/Makefile.in
include ssha256/Makefile.in
include ssha512/Makefile.in
include aes/Makefile.in
include ssm3/Makefile.in

all: $(TARGETS)

synth-all: $(SYNTH_TARGETS)

sim-all: $(SIM_TARGETS)

lint-all: $(LINT_TARGETS)

prove-all: $(PROVE_TARGETS)

print-synth-targets:
	@echo $(SYNTH_TARGETS) | sed "s/ /\n/g"

print-sim-targets:
	@echo $(SIM_TARGETS) | sed "s/ /\n/g"

