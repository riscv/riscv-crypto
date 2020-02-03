
BUILD_DIR = $(REPO_BUILD)/rtl
YOSYS     = $(YOSYS_ROOT)/yosys

SYNTH_TARGETS   =
SIM_TARGETS     =
TARGETS         =

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

define map_waves
$(call map_build_dir,${1})/${1}.vcd
endef

define map_sim_exe
$(call map_build_dir,${1})/${1}.sim
endef

define map_sim_log
$(call map_build_dir,${1})/${1}.simlog
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
        -p "flatten" \
	    -p "tee -o $(call map_synth_rpt,${1}).ltp ltp" \
        -p "synth -top ${3} -flatten" \
        -p "tee -o $(call map_synth_rpt,${1}) scc" \
        -p "write_verilog $(call map_synth_verilog,${1})" \
	    -p "tee -a $(call map_synth_rpt,${1}) stat" \
	    -p "tee -a $(call map_synth_rpt,${1}) ltp" \
        #-p "dfflibmap -liberty $(YOSYS_ROOT)/techlibs/common/cells.lib" \
        #-p "abc -liberty $(YOSYS_ROOT)/examples/cmos/cmos_cells.lib" \
        #-p "write_verilog $(call map_cmos_verilog,${1})" \
        #-p "tee -a $(call map_synth_rpt,${1}) stat" \

synth-${1} : $(call map_synth_rpt,${1})

TARGETS += synth-${1}
SYNTH_TARGETS += synth-${1}
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
include ssha3/Makefile.in
include aes/Makefile.in

all: $(TARGETS)

synth-all: $(SYNTH_TARGETS)

sim-all: $(SIM_TARGETS)

print-synth-targets:
	@echo $(SYNTH_TARGETS) | sed "s/ /\n/g"

print-sim-targets:
	@echo $(SIM_TARGETS) | sed "s/ /\n/g"

