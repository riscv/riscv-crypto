
BUILD_DIR = $(REPO_BUILD)/rtl/lut4

define map_build_dir
$(BUILD_DIR)/${1}
endef

define map_synth_verilog
$(call map_build_dir,${1})/${1}.v
endef

define map_synth_rpt
$(call map_build_dir,${1})/${1}.v
endef

#
# 1. Target Name
# 2. Source Files
define add_synth_target

$(call map_synth_rpt,${1}) : ${2}
	@mkdir -p $(call map_build_dir,${1})
	yosys -qQT \
        -p "read_verilog ${2}" \
        -p "synth" \
        -p "write_verilog $(call map_synth_verilog,${1})" \
	    -p "tee -o $(call map_synth_rpt,${1}) stat" \
	    -p "tee -a $(call map_synth_rpt,${1}) ltp" 

${1} : $(call map_synth_rpt,${1})
endef


$(eval $(call add_synth_target,lut4_rv64,lut4_rv64.v))
