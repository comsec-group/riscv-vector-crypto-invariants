# Structure:

# 1. Build 3D list of experiments, first index is experiment, second index is report number and third index is a dict with invariant names as keys and tuple (bound, time) as values

# From this data structure, we will then draw our analysis, and put the results into dicts with the invariant.
# Metrics we will measure:
# - average time for invariant to reach proof
# - percentage of invariant having reached a proof vs not
# - average bound of invariant at the end on not reaching proof, and average time that bound was first reached

# In a second and third iteration we will determine:
# - for result: which experiment the highest bound was reached the fastest (if multiple times), saved as a list of the invariants that were active for that.
# - for result: which invariants were active whenever the result reached its highest bound, giving each a point.
# - for result: time saved on result bound time (every time result reached highest bound faster than average, add time difference to score of each invariant active that time)
# - for all assertions: which invaraints were active the most when the assertion reached proof (or bound if never proven) faster than average (ranked list, influence points)
# - for all assertions: which invariants were active whenever the assertion reached proof, and how much time was saved (ranked list, influence time saved on proof)
# - from the previous data, which invariants saved the other invariants the most time on the proof (if proof) or helped them reach the highest bound (most distance from average bound) (influence beneficial to bound)

# Finally, we will produce a csv file with all of these final results from the two iterations in it:
# - average time on proof
# - average bound and time it was reached
# - success chance
# - beneficial to result bound
# - time saved for result bound time
# - points for active while other invariant reached highest bound
# - ranked lists for:
# - influence points on proof
# - influence beneficial to bounds
import csv
import os
import re
from collections import defaultdict




# Finction to read the assertion names file and return a list of assertion names, including the result assertion at the top.
def read_assertion_names(assertion_names_path):
    with open(assertion_names_path, 'r') as f:
        assertion_names = [line.strip() for line in f.readlines()]
    return assertion_names

def get_assertion_group(assertion_str):
    return re.search(r'(?<=_g)[0-9]+$',assertion_str)

# Function to parse each CSV file and extract the required data
def extract_data_from_csv(csv_path, assertion_names):
    data = defaultdict()

    with open(csv_path, mode='r', newline='') as file:
        reader = csv.reader(file)
        # Skip the header
        next(reader)

        # Process each row
        for row in reader:
            name = row[1]
            result = row[4]
            time = row[5]
            
            # Only consider relevant names (result_is_valid or _g[#])
            if name in assertion_names:
                # Parse result and time
                if result == 'Infinite':
                    bound = 'Infinite'
                else:
                    bound = int(re.findall('\d+', result)[0])
                
                # Handle the time string, e.g., '0.000 s' or '179.715 s'
                if 's' in time:
                    time_value = time.replace(' s', '')
                    time_value = float(time_value)
                else:
                    time_value = None

                # Store the tuple (bound, time)
                data[name] = (bound, time_value)

    return data



def collect_experiment_data(assertion_names, report_dir, file_prefix, experiment_counter, rapidfire_counter, regular_report_counter):
    outdata = list(list(dict()))
    
    for experiment_idx in range(1, experiment_counter + 1):
        curr_report_data = list(dict())
        # get rapidfire first
        for rapidfire_idx in range(1, rapidfire_counter + 1):
            # prepare the filename to be read
            file_suffix = "rapidfire_{0}_{1}.csv".format(experiment_idx, rapidfire_idx)
            filename = file_prefix + file_suffix
            file_path = os.path.join(report_dir, filename)
            # read the filedata into the corresponding location
            curr_report_data.append(extract_data_from_csv(file_path, assertion_names))
        
        #now get the regular reports
        for report_idx in range(1, regular_report_counter + 1):
            # prepare the filename to be read
            file_suffix = "{0}_{1}.csv".format(experiment_idx, report_idx)
            filename = file_prefix + file_suffix
            file_path = os.path.join(report_dir, filename)
            # read the filedata into the corresponding location, shifted by the already read rapidfire data
            curr_report_data.append(extract_data_from_csv(file_path, assertion_names))
        outdata.append(curr_report_data)
    # return the outdata file, containing a 2D list of dictionaries
    return outdata
    
    
    
    
def analyze_data(data_collection, output_dir, assertion_names):
    
    # we initialize the relevant datastructures:
    
    #will be measured in first loop
    average_time_on_proof = defaultdict(float)
    average_bound_on_fail = defaultdict(float)
    average_time_to_bound_on_fail = defaultdict(float) #the time it has taken until whatever bound was reached, relevant to see if jasper got stuck fast or ran the entire time.
    success_chance = defaultdict(float)
    
    fastest_time_for_highest_bound = defaultdict(lambda: (int, float, int)) # (bound, time, experiment_nr) find highest bound first and then find the first time that bound was reached within that experiment and how long it took
    
    # will be measured in second loop
    best_result_active_invariants = list()
    influence_time_benefited_on_proof = defaultdict(lambda: defaultdict(float)) # ordered list of invariants that most impacted the time to proof for an invariant compared to average time to proof, only for those who reached proof at least once
    influence_benefited_on_bound = defaultdict(lambda: defaultdict(float)) # ordered list of invariants that most impacted the bound for an invariant (not time to bound, actual bound) if the bound was above the average bound (requires at least two different bounds to have been reached)
    influence_on_time_to_proof = defaultdict(float) # total sum of time saved on proof for other invariants due to this one
    influence_on_bound = defaultdict(int) # amount of times another assertion had an increase in bound due to this one
    influence_on_proof = defaultdict(int) # amount of times another assertion proved while this one was active (regardless of proof speed)
    
    
    # internal data structures (not directly for output)
    success_counter = defaultdict(int)
    failure_counter = defaultdict(int)
    bound_on_fail_total = defaultdict(int) # for average bound
    highest_bound = defaultdict(int)
    times_to_proof_total = defaultdict(float) # for average time
    times_to_bounds_total = defaultdict(float) # fastest time respectively for the last bound reached
    times_to_bounds = defaultdict(lambda: list()) # for the result we need all times to bound.
    times_to_highest_bound = defaultdict(lambda: list()) # time it took to reach highest bound, if new highest bound found list is emptied and started anew. tuple with (time, experiment_nr)
    report_nr_proof_reached = defaultdict(lambda: defaultdict()) #at what point in the experiment, measured by report count, the assertion reached a proof
    report_nr_bound_reached = defaultdict(lambda: defaultdict()) #at what point in the experiment, measured by report count, the assertion reached its highest bound
    
    
    
    
    # we will have several values that we can simply deduce from the last log, such as the highest bound, success and failure counter, time to proof, etc.
    # other values, such as fastest time to bound and other times related to bound will have to be calculated based on other logs.
    
    
    for experiment_idx, experiment in enumerate(data_collection):
        
        #save succesful assertions for an experiment, so that these wont be evaulated for bounds in earlier tests
        # save last bound for all assertions that are bounded, to find the last bound for an assertion
        current_experiment_successful_assertions = list()
        current_experiment_last_bound = defaultdict(int)
        current_experiment_time_to_bound = defaultdict(float)
        current_experiment_proof_flag = defaultdict(bool) # this flag ensures that the proof time is only set once per assertion and experiment
        current_experiment_bound_flag = defaultdict(bool)
        
        #we iterate through the reports in reverse order to get the last report on the first iteration.
        for report_idx, report in enumerate(reversed(experiment)):
            
            for assertion, value_tuple in report.items():
                
                # on last report, get all values that only need the last report:
                if report_idx == 0:
                    # if the assertion succeeded, mark it as a success and add it to time_to_proof
                    if value_tuple[0] == 'Infinite':
                        success_counter[assertion] += 1
                        times_to_proof_total[assertion] += value_tuple[1]
                        current_experiment_successful_assertions.append(assertion)
                    else:
                        failure_counter[assertion] += 1
                        bound_on_fail_total[assertion] += value_tuple[0]
                        current_experiment_last_bound[assertion] = value_tuple[0]
                        current_experiment_time_to_bound[assertion] = value_tuple[1]
                    # set flag for later steps
                    current_experiment_proof_flag[assertion] = False
                    current_experiment_bound_flag[assertion] = False
                
                # on all other reports, scan for the rest of the data
                else: 
                    if assertion in current_experiment_successful_assertions:
                        if value_tuple[0] != 'Infinite' and current_experiment_proof_flag[assertion] == False:
                            current_experiment_proof_flag[assertion] = True
                            report_nr_proof_reached[assertion][experiment_idx] = (len(experiment) - report_idx - 1)
                    
                    if assertion not in current_experiment_successful_assertions:
                        if value_tuple[0] == current_experiment_last_bound[assertion]:
                            current_experiment_time_to_bound[assertion] = value_tuple[1]
                        elif current_experiment_bound_flag[assertion] == False:
                            current_experiment_bound_flag[assertion] = True
                            report_nr_bound_reached[assertion][experiment_idx] = (len(experiment) - report_idx - 1)

                # on the first report (which is iterated over last) we append the bound times to our lists
                if report_idx == len(experiment) - 1:
                    times_to_bounds_total[assertion] += current_experiment_time_to_bound[assertion]
                    if highest_bound[assertion] < current_experiment_last_bound[assertion]:
                        highest_bound[assertion] = current_experiment_last_bound[assertion]
                        times_to_highest_bound[assertion] = list()
                        times_to_highest_bound[assertion].append((current_experiment_time_to_bound[assertion], experiment_idx))
                    elif highest_bound[assertion] == current_experiment_last_bound[assertion]:
                        times_to_highest_bound[assertion].append((current_experiment_time_to_bound[assertion], experiment_idx))
                    # add time to bound to the list. since current_experiment_time_to_bound is a defaultdict, it will just add a 0.0 if a proof was reached and no bound time recorded.
                    # this is intended, as it will help us presrve indexing of the list by experiment_idx (we only add to the list once per experiment, on the last report iterated over)
                    times_to_bounds[assertion].append(current_experiment_time_to_bound[assertion])
                        
                        
    for assertion in assertion_names:
        success_chance[assertion] = success_counter[assertion] / (failure_counter[assertion] + success_counter[assertion])
        if success_counter[assertion] != 0:
            average_time_on_proof[assertion] = times_to_proof_total[assertion] / success_counter[assertion]
        if failure_counter[assertion] != 0:
            average_bound_on_fail[assertion] = bound_on_fail_total[assertion] / failure_counter[assertion]
            average_time_to_bound_on_fail[assertion] = times_to_bounds_total[assertion] / failure_counter[assertion]
        
        if highest_bound[assertion] != 0:
            fastest_time_bound_tuple = min(times_to_highest_bound[assertion], key=lambda k: k[0])
            fastest_time_for_highest_bound[assertion] = (highest_bound[assertion], fastest_time_bound_tuple[0], fastest_time_bound_tuple[1])
        else:
            fastest_time_for_highest_bound[assertion] = (-1, -1.0, -1)
        
    
    
    # in a second loop, we will use all of the results from our first loop to evaluate the remaining data
    for experiment_idx, experiment in enumerate(data_collection):
        
        current_experiment_successful_assertions = list()
        
        # we only need the last report for this comparison, and the values we already gained from the previous loop
        report = experiment[-1]
        
        # the assertion in this first loop is the influencing assertion
        for assertion, value_tuple in report.items():
            
            # we don't need to look at the influence of the result assertion
            if assertion == assertion_names[0]:
                continue
            
            # get best result active invariants:
            if experiment_idx == fastest_time_for_highest_bound[assertion_names[0]][2]:
                best_result_active_invariants.append(assertion)
                
            
            # only check influence if the assertion reached a proof
            if value_tuple[0] != 'Infinite':
                continue
            
            # the assertion in this loop is the asertion being influenced
            for comp_assertion, comp_value_tuple in report.items():
                
                # if the comp_assertion is in the same group as the assertion, continue
                # this is to mitigate influence being high for assertions that always assert together and influence eachother that way
                # otherwise, larger groups would in some cases naturally have "better" values
                if get_assertion_group(assertion) == get_assertion_group(comp_assertion):
                    continue
                
                # if the comp_assertion succeeded and the assertion found a proof before the comp_assertion did
                if comp_value_tuple[0] == 'Infinite' and report_nr_proof_reached[comp_assertion][experiment_idx] > report_nr_proof_reached[assertion][experiment_idx]:
                    influence_on_proof[assertion] += 1
                    
                    # if the comp_assertion proved faster than average
                    if comp_value_tuple[1] < average_time_on_proof[comp_assertion]:
                        influence_on_time_to_proof[assertion] += (average_time_on_proof[comp_assertion] - comp_value_tuple[1])
                        influence_time_benefited_on_proof[comp_assertion][assertion] += (average_time_on_proof[comp_assertion] - comp_value_tuple[1])
                
                # if the compt_assertion did not succeed but the assertion found a proof before the comp assertion reached its highest bound
                elif comp_value_tuple[0] != 'Infinite' and report_nr_bound_reached[comp_assertion][experiment_idx] > report_nr_proof_reached[assertion][experiment_idx]:
                    if comp_value_tuple[0] > average_bound_on_fail[comp_assertion]:
                        influence_on_bound[assertion] += 1
                        influence_benefited_on_bound[comp_assertion][assertion] += (comp_value_tuple[0] - average_bound_on_fail[comp_assertion])
    
    
    # print all of the analyzed data into the output_dir as a csv file (already in output dir with filename)
    outlist = list()
    outlist.append(["Name", "Success chance", "Average time on proof", "Average bound on fail", "Average time to bound on fail", "Fastest time for highest bound", "Part of best result", "Influence on proof", "Influence on time to proof", "Influence on bound"])
    
    for assertion in assertion_names:
        
        dummy = list()
        dummy.append(assertion)
        dummy.append(success_chance[assertion])
        dummy.append(average_time_on_proof[assertion])
        dummy.append(average_bound_on_fail[assertion])
        dummy.append(average_time_to_bound_on_fail[assertion])
        dummy.append(fastest_time_for_highest_bound[assertion])
        
        #wether the assertion was part of the best experiment
        if assertion in best_result_active_invariants:
            dummy.append(True)
        else:
            dummy.append(False)
        
        dummy.append(influence_on_proof[assertion])
        dummy.append(influence_on_time_to_proof[assertion])
        dummy.append(influence_on_bound[assertion])
        
        outlist.append(dummy)
        
    formatting = list()
    formatting.append("Influence benefited to proof time:")
    outlist.append(formatting)
    for assertion in assertion_names:
        dummy = list()
        dummy.append(assertion)
        sorted_influence = sorted(influence_time_benefited_on_proof[assertion].items(), key = lambda kv: kv[1], reverse=True)
        dummy.extend(sorted_influence)
        
        outlist.append(dummy)
        
    formatting = list()
    formatting.append("Influence benefited to bound:")
    outlist.append(formatting)
    for assertion in assertion_names:
        dummy = list()
        dummy.append(assertion)
        sorted_influence = sorted(influence_benefited_on_bound[assertion].items(), key = lambda kv: kv[1], reverse=True)
        dummy.extend(sorted_influence)
        
        outlist.append(dummy)
        
    # write to the file
    with open(output_dir, 'w', newline='') as output_file:
        writer = csv.writer(output_file)
        writer.writerows(outlist)
    
    print("Report has been written to: {0}".format(output_dir))



if __name__ == '__main__':
    #intitalize all relevant parameters
    script_dir = os.path.dirname(os.path.realpath(__file__))
    logs_dir = os.path.join(script_dir, "../logs")
    reports_dir = os.path.join(logs_dir, "out_files") #output reports will be here
    invariant_names = os.path.join(reports_dir, "invariant_names.txt") #file with list of all invariant names will be here
    final_summary_location = os.path.join(script_dir, "final_report.csv")
    report_prefix = "test_output_TESTNAME_LOGS" # has to be set according to the name chosen in the advanced_testruns file
    experiment_count = 63 # going from 1 to experiment_count ((2**group_count - 1) * runs_per_permutation)
    rapidfire_count = 50 # going from 1 to rapidfire_count
    regular_report_count = 359 # going from 1 to regular_report_count
    
    
    assertion_names = read_assertion_names(invariant_names)
    
    experiment_data = collect_experiment_data(assertion_names, reports_dir, report_prefix, experiment_count, rapidfire_count, regular_report_count)
    
    analyze_data(experiment_data, final_summary_location, assertion_names)
    

