# structure:


# get all helper assertions from original script.

# use binary switch to enable/disable all permutations of assertions in loop, grouping assertions together that do the same thing.

# create temporary run.NAME.tcl script that will be executed, run the proof, and after writeback start the next loop iteration.

# change the report statement to make a new file, numbered according to the iteration of the loop. [vcryptu_report_]

import os
import subprocess
import re
import itertools
import glob


# relevant variables

#TODO: THE FOLLOWING COMMAND HAS TO BE INSERTED ACCORDING TO THE TOOL USED.
#THE PROVIDED EXAMPLE IS NOT A WORKING INSTRUCTION AND DUE TO LICENCING HAS TO BE INSERTED BY THE
tool_startup_command = "tool-version -no_ui"

script_dir = os.path.dirname(os.path.realpath(__file__))
logs_dir = os.path.join(script_dir, "../logs")

orig_script  = os.path.join(script_dir, "../run.SCRIPTNAME.tcl")
working_script = os.path.join(script_dir, "../run.STRIPPED_SCRIPT.tcl")
prove_config_template = os.path.join(script_dir, "tcl_template.txt")
project_dir = os.path.join(logs_dir, "logs/testrun") #project directories will go here
out_dir = os.path.join(logs_dir, "out_files") #output reports will go here
invariant_names = os.path.join(out_dir, "invariant_names.txt")
test_name = "TESTNAME_LOGS" #name to use for logfiles
group_count = 6 #groups are indexed starting at 1 going up to group_count.
runs_per_permutation = 1 #default should be 1, on higher count takes average of multiple runs.
time_per_run = 3600000 #time in miliesconds until attempt ends
result_assertion_name = "result_is_valid" #tell the program what the relevant assertion is
use_assumptions = False #if true, turns all assert -helper statements into assume statements, if false, leaves them as helpers
logging_interval = 10000 #interval of logging in miliseconds, default is 10000
rapidfire_loggin_interval = 200 #interval of rapidfire logging in miliseconds, default is 100 (rapidifire logging logs at that interval until first regular logging interval is reached)
continue_previous_attempt = True #if this is True, the script will only continue from the point that it previously left off, based on existing logs in out_dir. If false, it starts at the beginning.
max_log_count_per_run = int(time_per_run/logging_interval - 1)


#in case this is a continuation, this will check the logs for the last completed run and return its index
def get_idx_last_completed(name, group_count, runs_per_permutation, out_dir, max_log_count):
    permutation_count = (2**group_count - 1)*runs_per_permutation
    
    for index in range(1, permutation_count):
        filename = out_dir + '\\test_output_{0}_{1}_{2}.csv'.format(name, index, max_log_count)
        if not glob.glob(filename):
            return index


# read all helper assertions and the linenumber of the first assertion
def read_helpers(tcl_dir: str):
    with open(tcl_dir) as f:
        lines = [line.rstrip("\n") for line in f]
    
    invariant_name_match = r"(?<=-name ).*_g[0-9]+"
    outlist = list()
    pre_outlist = list()
    invariant_name_list = list()
    
    for i in range(1,group_count+1):
        groupmatch = r"^(assert -helper).*(_g" + str(i) + r")$"
        templist = list()
        line_number = 1
        for x in lines:
            if re.search(groupmatch, x):
                if use_assumptions == True:
                    assumption = x.replace('assert -helper', 'assume')
                    templist.append(assumption)
                else:
                    templist.append(x)
                if (i == 1) and (len(templist) == 1):
                    helper_start = line_number
            line_number += 1
        outlist.append(templist)
    
    f.close()
    
    for assertion_group in outlist:
        for assertion in assertion_group:
            invariant_name = re.search(invariant_name_match, assertion).group(0)
            invariant_name_list.append(invariant_name)
    
    return outlist, helper_start, invariant_name_list

# read the rest of the script
def read_tcl(tcl_dir: str):
    with open(tcl_dir) as f:
        lines = [line.rstrip("\n") for line in f]
    outlist = [x for x in lines if not (re.search(r'^(assert -helper).*', x) or re.search(r'^(prove ).*', x))]
    f.close()
    return outlist

def create_combinations(grouped_lists : list):
    outlist = list()
    
    for i in range(1, len(grouped_lists) + 1):
        combinations = itertools.combinations(grouped_lists, i)
        for e in combinations:
            outlist.append(list(e))
    
    return outlist

def flatten(list_of_lists):
    return [x for list in list_of_lists for x in list]

def flatten_helpers(perm_list: list):
    ret_list = list()
    for e in perm_list:
        new_e = flatten(e)
        ret_list.append(new_e)
    return ret_list


def create_prove_config(proof_config_file, logging_interval, rapidfire_interval, time_limit, permutation, name, log_directory):
    config = list()
    with open(proof_config_file) as f:
        lines = [line.rstrip("\n") for line in f]
    
    for line in lines:
        if line == "<SET_VARIABLES>":
            config.append("set interval {0}".format(logging_interval))
            config.append("set rapidfire_interval {0}".format(rapidfire_interval))
            config.append("set limit {0}".format(int(time_limit/logging_interval))) #this is the amount of iterations until time limit is reached, so time_limit/logging_interval
        elif line == "<SET_REPORT_RAPID>":
            config.append("        report -results -csv -file {0}/test_output_{1}_rapidfire_{2}_${{rapidfire_iterator}}.csv -force".format(log_directory, name, permutation))
        elif line == "<SET_REPORT>":
            config.append("    report -results -csv -file {0}/test_output_{1}_{2}_${{iterator}}.csv -force".format(log_directory, name, permutation))
        else:
            config.append(line)
    
    return config


# BEGINNING OF EXECUTION (too lazy to write main)

helper_list, line_number, helper_names = read_helpers(orig_script)
rest_of_script = read_tcl(orig_script)


#create list of helpers as separate file for later step
with open(invariant_names, "w+") as f:
    
    f.write("%s\n" %result_assertion_name)
    for item in helper_names:
        f.write("%s\n" %item)
    f.close

    
    
# This list contains 2**group_count - 1 lists, each of them with a different permutation of the 10 lists given initially.
# Each permutation itsself contains lists of strings, because the elements are the groups of assertions.
# This is why the flatten_helpers function goes through the permutations list, and flattens every list of lists within. 
# This way permutations_list is now no longer a list of lists of lists of strings, and instead just a list of lists of strings.
# That is what we want.
permutations_list = flatten_helpers(create_combinations(helper_list))

#set the starting point of the experiments. starting_index is indexed from 1 to (2**group_count - 1)*runs_per_permutation (The total amount of experiments to be made)
if continue_previous_attempt:
    starting_index = get_idx_last_completed(test_name, group_count, runs_per_permutation, out_dir, max_log_count_per_run)
else:
    starting_index = 1


# iterate over all permutations and run the proof with them, putting the outputs into a csv file with the corresponding number.
for i, e in enumerate(permutations_list[starting_index-1:], starting_index-1):
    for j in range(1, runs_per_permutation + 1):
        final_script = list()
        for item in rest_of_script:
            final_script.append(item)
        
        for k in range(len(e)):
            final_script.insert(k + line_number, e[k])
        
        final_script.extend(create_prove_config(prove_config_template, logging_interval, rapidfire_loggin_interval, time_per_run, (i * runs_per_permutation + j), test_name, out_dir))

        with open(working_script, "w+") as f:
            for items in final_script:
                f.write("%s\n" %items)
            f.close
        
        # preparing arguments for subprocess command
        head, tail = os.path.split(working_script)
        log_project_dir = project_dir + "_{0}".format(i * runs_per_permutation + j)
        script_prompt = "{0} -tcl {1} -proj {2}".format(tool_startup_command, tail, log_project_dir)
        # starting evaluation of this iteration
        retval_subprocess = subprocess.run([script_prompt], shell = True, cwd = os.path.dirname(working_script))

