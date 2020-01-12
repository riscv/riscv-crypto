
BUILD_DIR = $(REPO_BUILD)/rtl/lut4

#
# 1. Target Name
# 2. Source Files
define add_synth_target

${1} : ${2}
	@mkdir -p $(BUILD_DIR)/${1}
	yosys -qQT \
        -p "read_verilog ${2}" \
        -p "synth" \
        -p "write_verilog $(BUILD_DIR)/${1}/${1}.v" \
	    -p "tee -o $(BUILD_DIR)/${1}/${1}.rpt stat" \
	    -p "tee -a $(BUILD_DIR)/${1}/${1}.rpt ltp" 

endef


$(eval $(call add_synth_target,lut4_rv64,lut4_rv64.v))
