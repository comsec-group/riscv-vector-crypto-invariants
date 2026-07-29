# Initiate your tool of choice and set up the following mappings to the C reference model from Spike.
# Make sure to blackbox the sram unit and configure the parameter NrLanes of Marian to 4, as otherwise it will not compile correctly.
#    NrLanes can be initiated at other values >=2 if the write_back unit is also blackboxed,
#    but the write_back unit only supports NrLanes = 4.


####################################
# mapping and relevant assumptions #
####################################

# perform the following mappings to spike, C++ variables defined by the specification naming.
#map from spec {operation} to marian var {{crypto_unit_imp.pe_req_i.op}} 

#map from spec {vd_0} to marian var {{crypto_unit_imp.crypto_operand_i[0][1][31:0]}}       
#map from spec {vd_1} to marian var {{crypto_unit_imp.crypto_operand_i[1][1][31:0]}}       
#map from spec {vd_2} to marian var {{crypto_unit_imp.crypto_operand_i[0][1][63:32]}}      
#map from spec {vd_3} to marian var {{crypto_unit_imp.crypto_operand_i[1][1][63:32]}}      

#map from spec {vs2_0} to marian var {{crypto_unit_imp.crypto_operand_i[0][0][31:0]}}      
#map from spec {vs2_1} to marian var {{crypto_unit_imp.crypto_operand_i[1][0][31:0]}}      
#map from spec {vs2_2} to marian var {{crypto_unit_imp.crypto_operand_i[0][0][63:32]}}     
#map from spec {vs2_3} to marian var {{crypto_unit_imp.crypto_operand_i[1][0][63:32]}}     

#map from spec {vs1_0} to marian var {{crypto_unit_imp.crypto_operand_i[0][2][31:0]}}      
#map from spec {vs1_1} to marian var {{crypto_unit_imp.crypto_operand_i[1][2][31:0]}}      
#map from spec {vs1_2} to marian var {{crypto_unit_imp.crypto_operand_i[0][2][63:32]}}     
#map from spec {vs1_3} to marian var {{crypto_unit_imp.crypto_operand_i[1][2][63:32]}}     


# Assume the C++ inputs are stable as we do not simulate timing of the C++ calculations.

#########################
# constraints for proof #
#########################

# Constrain inputs of the operation to inputs that are already filtered out by surrounding logic
# in the System. For Marian, we use minimal constraints for the operation:
# for this example, we constrain element width and 

assume { crypto_unit_imp.pe_crypto_req_coll_s.scalar_op == 64'd0 } -name op_scalar
assume { crypto_unit_imp.pe_req_i.vfu == crypto_unit_imp.ara_pkg.VFU_CryptoUnit } -name op_vfu
assume { crypto_unit_imp.pe_crypto_req_coll_s.vl == 12'd8 } -name op_vl
assume { crypto_unit_imp.pe_crypto_req_coll_s.vstart == 12'd0 } -name op_vstart
assume { (crypto_unit_imp.pe_crypto_req_coll_s.vtype.vsew == crypto_unit_imp.rvv_pkg.EW32) or (crypto_unit_imp.pe_crypto_req_coll_s.vtype.vsew == crypto_unit_imp.rvv_pkg.EW64) } -name op_vsew
assume { crypto_unit_imp.pe_crypto_req_coll_s.vtype.vlmul == crypto_unit_imp.rvv_pkg.LMUL_1} -name op_vlmul


#########################
# result assertion      #
#########################

#in this case, check if the output of the execution units matches the output of the C++ model to ensure computational correctness.
assert {crypto_unit_imp.i_execution_units.result_valid_o  |-> crypto_unit_imp.crypto_result_s[256-1:0] == {vd_out_7, vd_out_6, vd_out_5, vd_out_4, vd_out_3, vd_out_2, vd_out_1, vd_out_0} } -name  result_is_valid
cover {crypto_unit_imp.pe_req_valid_q} -name pe_req_valid_q


#########################
# Invariants            #
#########################
assert -helper { (crypto_unit_imp.i_pe_fifo.full_o && crypto_unit_imp.i_pe_fifo.empty_o) == 1'b0 } -name pe_fifo_fill_level
assert -helper { (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) |=> ( crypto_unit_imp.i_execution_units.result_valid_q ) } -name result_after_execution
assert -helper { crypto_unit_imp.i_execution_units.arg_valid_i |=> crypto_unit_imp.i_execution_units.result_valid_q } -name result_valid_after_arg_valid
assert -helper { crypto_unit_imp.i_operand_collector.arg_full_q[0] == 'b1 |-> $stable(crypto_unit_imp.i_operand_collector.gen_operand_logic[0].curr_operand_byte_idx_s) } -name operand_full_check_0
assert -helper { crypto_unit_imp.i_operand_collector.arg_full_q[1] == 'b1 |-> $stable(crypto_unit_imp.i_operand_collector.gen_operand_logic[1].curr_operand_byte_idx_s) } -name operand_full_check_1
assert -helper { crypto_unit_imp.i_operand_collector.arg_full_q[2] == 'b1 |-> $stable(crypto_unit_imp.i_operand_collector.gen_operand_logic[2].curr_operand_byte_idx_s) } -name operand_full_check_2
assert -helper { (crypto_unit_imp.i_execution_units.arg_ready_s && crypto_unit_imp.i_execution_units.result_valid_d && (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2MS)) |-> (crypto_unit_imp.i_execution_units.crypto_result_d == crypto_unit_imp.i_execution_units.msg_sched_result_s) } -name execution_unit_mux_sha2ms
assert -helper { (crypto_unit_imp.i_execution_units.arg_ready_s && crypto_unit_imp.i_execution_units.result_valid_d && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL))) |-> (crypto_unit_imp.i_execution_units.crypto_result_d[127:0] == crypto_unit_imp.i_execution_units.compr_result_s) } -name execution_unit_mux_sha2ch/cl
assert -helper { ((crypto_unit_imp.i_operand_collector.gen_operand_logic[0].operand_bytes_read_q == crypto_unit_imp.i_operand_collector.operand_bytes_total_s)&&(crypto_unit_imp.i_operand_collector.pe_req_ack_s)) |-> crypto_unit_imp.i_operand_collector.gen_operand_logic[0].operand_bytes_read_d == 'b0} -name counter_read_reset_0
assert -helper { ((crypto_unit_imp.i_operand_collector.gen_operand_logic[1].operand_bytes_read_q == crypto_unit_imp.i_operand_collector.operand_bytes_total_s)&&(crypto_unit_imp.i_operand_collector.pe_req_ack_s)) |-> crypto_unit_imp.i_operand_collector.gen_operand_logic[1].operand_bytes_read_d == 'b0} -name counter_read_reset_1
assert -helper { ((crypto_unit_imp.i_operand_collector.gen_operand_logic[2].operand_bytes_read_q == crypto_unit_imp.i_operand_collector.operand_bytes_total_s)&&(crypto_unit_imp.i_operand_collector.pe_req_ack_s)) |-> crypto_unit_imp.i_operand_collector.gen_operand_logic[2].operand_bytes_read_d == 'b0} -name counter_read_reset_2


assert -helper { crypto_unit_imp.crypto_operand_valid[0][0] |->  crypto_unit_imp.crypto_operand[0][0] == $past(crypto_unit_imp.crypto_operand_i[0][0],1)} -name fifo_data_order_l0vs2
assert -helper { crypto_unit_imp.crypto_operand_valid[1][0] |->  crypto_unit_imp.crypto_operand[1][0] == $past(crypto_unit_imp.crypto_operand_i[1][0],1)} -name fifo_data_order_l1vs2

assert -helper { crypto_unit_imp.crypto_operand_valid[0][1] |->  crypto_unit_imp.crypto_operand[0][1] == $past(crypto_unit_imp.crypto_operand_i[0][1],1)} -name fifo_data_order_l0vd
assert -helper { crypto_unit_imp.crypto_operand_valid[1][1] |->  crypto_unit_imp.crypto_operand[1][1] == $past(crypto_unit_imp.crypto_operand_i[1][1],1)} -name fifo_data_order_l1vd

assert -helper { crypto_unit_imp.crypto_operand_valid[0][2] |->  crypto_unit_imp.crypto_operand[0][2] == $past(crypto_unit_imp.crypto_operand_i[0][2],1)} -name fifo_data_order_l0vs1
assert -helper { crypto_unit_imp.crypto_operand_valid[1][2] |->  crypto_unit_imp.crypto_operand[1][2] == $past(crypto_unit_imp.crypto_operand_i[1][2],1)} -name fifo_data_order_l1vs1

assert -helper { crypto_unit_imp.i_pe_fifo.data_i.vtype.vsew == crypto_unit_imp.pe_req_i.vtype.vsew } -name pe_fifo_data_i_vsew

assert -helper { crypto_unit_imp.i_operand_collector.pe_req_valid_i |-> crypto_unit_imp.i_operand_collector.operand_active_s[0] == crypto_unit_imp.pe_req_i.use_vs2 } -name active_operands_vs2
assert -helper { crypto_unit_imp.i_operand_collector.pe_req_valid_i |-> crypto_unit_imp.i_operand_collector.operand_active_s[1] == crypto_unit_imp.pe_req_i.use_vd } -name active_operands_vd
assert -helper { crypto_unit_imp.i_operand_collector.pe_req_valid_i |-> crypto_unit_imp.i_operand_collector.operand_active_s[2] == crypto_unit_imp.pe_req_i.use_vs1 } -name active_operands_vs1


assert -helper { crypto_unit_imp.i_operand_collector.gen_operand_logic[0].operand_bytes_read_d <= crypto_unit_imp.i_operand_collector.operand_bytes_total_s } -name counter_read_upper_limit_0
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[0] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[0] && crypto_unit_imp.i_operand_collector.operand_active_s[0] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[0]) |-> (crypto_unit_imp.i_operand_collector.gen_operand_logic[0].operand_bytes_remaining_s == crypto_unit_imp.ara_pkg.OperandBytes - crypto_unit_imp.i_operand_collector.gen_operand_logic[0].curr_operand_byte_idx_s) } -name counter_down_set_0
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[0] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[0] && crypto_unit_imp.i_operand_collector.operand_active_s[0] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[0]) |=> crypto_unit_imp.i_operand_collector.gen_operand_logic[0].operand_bytes_remaining_s <= $past(crypto_unit_imp.i_operand_collector.gen_operand_logic[0].operand_bytes_remaining_s, 1) } -name operand_bytes_remaining_counts_down_0
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[0] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[0] && crypto_unit_imp.i_operand_collector.operand_active_s[0] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[0]) |-> crypto_unit_imp.i_operand_collector.gen_operand_logic[0].operand_bytes_read_d >= $past(crypto_unit_imp.i_operand_collector.gen_operand_logic[0].operand_bytes_read_d, 1) } -name operand_bytes_read_counts_up_0

assert -helper { crypto_unit_imp.i_operand_collector.gen_operand_logic[1].operand_bytes_read_d <= crypto_unit_imp.i_operand_collector.operand_bytes_total_s } -name counter_read_upper_limit_1
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[1] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[1] && crypto_unit_imp.i_operand_collector.operand_active_s[1] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[1]) |-> (crypto_unit_imp.i_operand_collector.gen_operand_logic[1].operand_bytes_remaining_s == crypto_unit_imp.ara_pkg.OperandBytes - crypto_unit_imp.i_operand_collector.gen_operand_logic[1].curr_operand_byte_idx_s) } -name counter_down_set_1
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[1] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[1] && crypto_unit_imp.i_operand_collector.operand_active_s[1] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[1]) |=> crypto_unit_imp.i_operand_collector.gen_operand_logic[1].operand_bytes_remaining_s <= $past(crypto_unit_imp.i_operand_collector.gen_operand_logic[1].operand_bytes_remaining_s, 1) } -name operand_bytes_remaining_counts_down_1
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[1] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[1] && crypto_unit_imp.i_operand_collector.operand_active_s[1] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[1]) |-> crypto_unit_imp.i_operand_collector.gen_operand_logic[1].operand_bytes_read_d >= $past(crypto_unit_imp.i_operand_collector.gen_operand_logic[1].operand_bytes_read_d, 1) } -name operand_bytes_read_counts_up_1

assert -helper { crypto_unit_imp.i_operand_collector.gen_operand_logic[2].operand_bytes_read_d <= crypto_unit_imp.i_operand_collector.operand_bytes_total_s } -name counter_read_upper_limit_2
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[2] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[2] && crypto_unit_imp.i_operand_collector.operand_active_s[2] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[2]) |-> (crypto_unit_imp.i_operand_collector.gen_operand_logic[2].operand_bytes_remaining_s == crypto_unit_imp.ara_pkg.OperandBytes - crypto_unit_imp.i_operand_collector.gen_operand_logic[2].curr_operand_byte_idx_s) } -name counter_down_set_2
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[2] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[2] && crypto_unit_imp.i_operand_collector.operand_active_s[2] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[2]) |=> crypto_unit_imp.i_operand_collector.gen_operand_logic[2].operand_bytes_remaining_s <= $past(crypto_unit_imp.i_operand_collector.gen_operand_logic[2].operand_bytes_remaining_s, 1) } -name operand_bytes_remaining_counts_down_2
assert -helper { (!crypto_unit_imp.i_operand_collector.arg_full_q[2] && crypto_unit_imp.i_operand_collector.operand_logic_en_s && !crypto_unit_imp.i_operand_collector.pe_req_done_s[2] && crypto_unit_imp.i_operand_collector.operand_active_s[2] && crypto_unit_imp.i_operand_collector.crypto_operand_valid_trans_s[2]) |-> crypto_unit_imp.i_operand_collector.gen_operand_logic[2].operand_bytes_read_d >= $past(crypto_unit_imp.i_operand_collector.gen_operand_logic[2].operand_bytes_read_d, 1) } -name operand_bytes_read_counts_up_2

assert -helper { ($changed(crypto_unit_imp.i_execution_units.state_d)) && (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL)) |-> ( crypto_unit_imp.i_execution_units.i_sha.i_compression.t_a_32 == t_out_a ) } -name compression_intermediate_values_a
assert -helper { ($changed(crypto_unit_imp.i_execution_units.state_d)) && (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL)) |-> ( crypto_unit_imp.i_execution_units.i_sha.i_compression.t_b_32 == t_out_b ) } -name compression_intermediate_values_b
assert -helper { ($changed(crypto_unit_imp.i_execution_units.state_d)) && (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL)) |-> ( crypto_unit_imp.i_execution_units.i_sha.i_compression.t_c_32 == t_out_c ) } -name compression_intermediate_values_c
assert -helper { ($changed(crypto_unit_imp.i_execution_units.state_d)) && (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL)) |-> ( crypto_unit_imp.i_execution_units.i_sha.i_compression.t_d_32 == t_out_d ) } -name compression_intermediate_values_d
assert -helper { ($changed(crypto_unit_imp.i_execution_units.state_d)) && (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL)) |-> ( crypto_unit_imp.i_execution_units.i_sha.i_compression.t_e_32 == t_out_e ) } -name compression_intermediate_values_e
assert -helper { ($changed(crypto_unit_imp.i_execution_units.state_d)) && (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL)) |-> ( crypto_unit_imp.i_execution_units.i_sha.i_compression.t_f_32 == t_out_f ) } -name compression_intermediate_values_f
assert -helper { ($changed(crypto_unit_imp.i_execution_units.state_d)) && (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL)) |-> ( crypto_unit_imp.i_execution_units.i_sha.i_compression.t_g_32 == t_out_g ) } -name compression_intermediate_values_g
assert -helper { ($changed(crypto_unit_imp.i_execution_units.state_d)) && (crypto_unit_imp.i_execution_units.state_d == crypto_unit_imp.i_execution_units.EXEC) && ((crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CH) || (crypto_unit_imp.i_execution_units.pe_crypto_req_d.op == crypto_unit_imp.ara_pkg.VSHA2CL)) |-> ( crypto_unit_imp.i_execution_units.i_sha.i_compression.t_h_32 == t_out_h ) } -name compression_intermediate_values_h



####################
# start proof here #
####################

# When using our automated scripts, the proof hast to be run in the background.