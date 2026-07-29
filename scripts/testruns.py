# structure:


# get all helper assertions from original script.

# use binary switch to enable/disable all permutations of assertions in loop, grouping assertions together that do the same thing.

# create temporary run.NAME.tcl script that will be executed, run the proof, and after writeback start the next loop iteration.

# change the report statement to make a new file, numbered according to the iteration of the loop. [vcryptu_report_]

import os
import subprocess
import re
import itertools



# relevant variables

#TODO: THE FOLLOWING COMMAND HAS TO BE INSERTED ACCORDING TO THE TOOL USED.
#THE PROVIDED EXAMPLE IS NOT A WORKING INSTRUCTION AND DUE TO LICENCING HAS TO BE INSERTED BY THE
tool_startup_command = "tool-version -no_ui"

script_dir = os.path.dirname(os.path.realpath(__file__))

orig_script  = os.path.join(script_dir, "../run.SCRIPTNAME.tcl")
working_script = os.path.join(script_dir, "../run.STRIPPED_SCRIPTNAME.tcl")
out_dir = os.path.join(script_dir, "../out_files")
invariant_names = os.path.join(out_dir, "invariant_names.txt")
group_count = 4 #groups are indexed starting at 1 going up to group_count.
runs_per_permutation = 20 #default should be 1, on higher count takes average of multiple runs.
time_per_run = 60 #time in seconds
result_assertion_name = "result_is_valid" #tell the program what the relevant assertion is
use_assumptions = True #if true, turns all assert -helper statements into assume statements, if false, leaves them as helpers


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
    outlist = [x for x in lines if not re.search(r'^(assert -helper).*', x)]
    f.close()
    return outlist

# tcl command to save Jasper results to csv
def report(n: int):
    retstr = r"report -results -csv -file ./out_files/test_output_{0}.csv -force".format(n)
    return retstr

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


# BEGINNING OF EXECUTION (too lazy to write main)

helper_list, line_number, helper_names = read_helpers(orig_script)
rest_of_script_unchanged = read_tcl(orig_script)
rest_of_script = list()


#set time limit per run and silent
time_limit = " -time_limit {0} -silent".format(time_per_run)

#ensure that proof does not run in the background
for item in rest_of_script_unchanged:
    my_regex = r"^prove "
    
    if not re.search(my_regex, item):
        rest_of_script.append(item)
    else:
        rest_of_script.append(item.replace("-bg", "") + time_limit)

#create list of helpers as separate file for later step
with open(invariant_names, "w+") as f:
    
    f.write("%s\n" %result_assertion_name)
    for item in helper_names:
        f.write("%s\n" %item)
    f.close

    
    
# This list contains 2^{group_count} - 1 lists, each of them with a different permutation of the 10 lists given initially.
# Each permutation itsself contains lists of strings, because the elements are the groups of assertions.
# This is why the flatten_helpers function goes through the permutations list, and flattens every list of lists within. 
# This way permutations_list is now no longer a list of lists of lists of strings, and instead just a list of lists of strings.
# That is what we want.
permutations_list = flatten_helpers(create_combinations(helper_list))



# iterate over all permutations and run the proof with them, putting the outputs into a csv file with the corresponding number.
for i, e in enumerate(permutations_list):
    for j in range(1, runs_per_permutation + 1):
        final_script = list()
        for item in rest_of_script:
            final_script.append(item)
        
        for k in range(len(e)):
            final_script.insert(k + line_number, e[k])
        
        final_script.append(report(i*runs_per_permutation + j))
        final_script.append("exit")

        with open(working_script, "w+") as f:
            for items in final_script:
                f.write("%s\n" %items)
            f.close
        
        retval_subprocess = subprocess.run(["{0}} -tcl run.marian_execu_testing.tcl".format(tool_startup_command)], shell = True, cwd = os.path.dirname(working_script))

