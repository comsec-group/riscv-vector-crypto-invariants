# This file evaluates the measurements performed by the testruns.py file. It is intended for evaluation of verifications that manage to find a valid proof.
# The script will create an intermediate collection of all the output data, and a final report with the evaluation based on the metrics described in my thesis.

import csv
import os
import re
from collections import defaultdict


def extract_data_from_csv(csv_path, names):
    data = {name: (None, None) for name in names}  # Initialize dictionary with None for all names

    with open(csv_path, mode='r', newline='') as file:
        reader = csv.reader(file)
        # Skip the header
        next(reader)

        # Process each row
        for row in reader:
            name = row[1]
            result = row[4]
            time = row[5]
            
            # Only consider relevant names (result_is_valid or _g[1-10])
            if name in data:
                # Parse result and time
                if result == 'Infinite':
                    cycles = 'Infinite'
                else:
                    cycles = int(re.findall('\d+', result)[0])
                
                # Handle the time string, e.g., '0.000 s' or '179.715 s'
                if 's' in time:
                    time_value = time.replace(' s', '')
                    time_value = float(time_value)
                else:
                    time_value = None

                # Store the tuple (cycles, time)
                data[name] = (cycles, time_value)

    return data

# Function to create the master CSV from the data extracted
def create_master_csv(output_path, input_dir, names_file):
    # Read the names to consider from the file
    with open(names_file, 'r') as f:
        valid_names = [line.strip() for line in f.readlines()]

    # Prepare columns for the output
    cols = list(list())
    
    # Get all CSV files and sort them numerically
    files = [f for f in os.listdir(input_dir) if re.match(r"test_output_\d+\.csv", f)]
    
    # Sort the files numerically based on the number in the filename
    files.sort(key=lambda x: int(re.search(r"(\d+)", x).group(1)))  # Extract numbers and sort by them

    # Extract data for each file and append to the columns
    for i, filename in enumerate(files):
        
        working_col = list()
        init_col = list()
        
        # We only care about files with the correct naming scheme
        if re.match(r"test_output_\d+\.csv", filename):
            file_path = os.path.join(input_dir, filename)
            file_data = extract_data_from_csv(file_path, valid_names)

            # Add the data to columns in the form (name, (cycles, time))
            for name in valid_names:
                if i == 0:  # Add the name row once in the first column
                    init_col.append([name])

                cycles, time = file_data.get(name, (None, None))
                working_col.append(f"({cycles}, {time})")  # Append the tuple of (cycles, time)
        
        if i == 0:
            cols.append(init_col)
        
        cols.append(working_col)
    
    # Write the final master CSV
    with open(output_path, 'w', newline='') as output_file:
        writer = csv.writer(output_file)
        writer.writerows(cols)


def process_csv(input_file, output_file):
    
    # prepare needed data structures
    success_points = defaultdict(int)
    presence_points = defaultdict(int)
    success_not_sufficient_points = defaultdict(int)
    average_time_on_success = defaultdict(float)
    success_chance = defaultdict(float)
    influence_points = defaultdict(lambda: defaultdict(int))
    influence_time_benefited = defaultdict(lambda: defaultdict(float))
    influenced_others_points = defaultdict(int)
    influenced_others_time_saved = defaultdict(float)
    influenced_result_time_saved = defaultdict(float)
    
    # internal variables
    time_sum = defaultdict(float)
    successes = defaultdict(float)
    failures = defaultdict(float)
    
    with open(input_file, 'r') as f:
        reader = csv.reader(f)
        rows = list(reader)
        
    #header contains invariant names, experiments contains results
    raw_header = rows[0]
    experiments = rows[1:]
    header = list()
    
    #formatting the header
    for entry in raw_header:
        header.append(re.match(r'\[.+\]', entry).group(0)[2:-2])
    
    for row_idx, experiment in enumerate(experiments):
        
        #if experiment succeeded, process success_points and presence_points as well as time_sum and successes/failures
        success_val = re.match(r'\([a-zA-Z0-9]+,', experiment[0]).group(0) 
        success_val = success_val[1:-1]
        
        
        if success_val == 'Infinite':
            
            #check for every Invariant if it succeeded or not
            for col_idx, str_tuple in enumerate(experiment):
                
                invarant_result = re.match(r'\([a-zA-Z0-9]+,', str_tuple).group(0) 
                invarant_result = invarant_result[1:-1]
                
                #on a success, increment successes, increment time_sum by the time spent and give a success_point.
                if invarant_result == 'Infinite':
                    successes[header[col_idx]] += 1
                    time_sum[header[col_idx]] += float(re.search(r' [0-9]+.[0-9]+\)', str_tuple).group(0)[1:-1]) #this matches the float in the second half of the string tuple.
                    success_points[header[col_idx]] += 1
                    
                    
                #on a failure, gain a presence point and a failure count.
                elif invarant_result != 'None':
                    failures[header[col_idx]] += 1
                    presence_points[header[col_idx]] += 1
        
        #if experiment failed, process success_not_sufficient points as well as time_sum and successes/failures
        elif success_val != 'None':
            
            #check for every Invariant if it succeeded or not
            for col_idx, str_tuple in enumerate(experiment):
                
                invarant_result = re.match(r'\([a-zA-Z0-9]+,', str_tuple).group(0) 
                invarant_result = invarant_result[1:-1]
                
                #on a success, increment successes, increment time_sum by the time spent and give a success_not_sufficient point.
                if invarant_result == 'Infinite':
                    successes[header[col_idx]] += 1
                    time_sum[header[col_idx]] += float(re.search(r' [0-9]+.[0-9]+\)', str_tuple).group(0)[1:-1]) #this matches the float in the second half of the string tuple.
                    success_not_sufficient_points[header[col_idx]] += 1
                
                #on a failure, gain a failure count.
                elif invarant_result != 'None':
                    failures[header[col_idx]] += 1
    
    results = list(list())
    secondary_results = list(list())
    #collect all measurements and write them to a csv
    for idx, invariant in enumerate(header):
        dummy = list()
        dummy.append(invariant)
        dummy.append(success_points[invariant])
        dummy.append(presence_points[invariant])
        dummy.append(success_not_sufficient_points[invariant])
        
        average_time_on_success[invariant] = time_sum[invariant] / successes[invariant]
        dummy.append(average_time_on_success[invariant])
        
        success_chance[invariant] = successes[invariant] / (successes[invariant] + failures[invariant])
        dummy.append(success_chance[invariant])
        
        results.append(dummy)

    
    #calculate influence (needs previous results so has to be done separate)
    for row_idx, experiment in enumerate(experiments):
        
        for col_idx, str_tuple in enumerate(experiment):
            
            if re.match(r'\([a-zA-Z0-9]+,', str_tuple).group(0)[1:-1] != 'Infinite' or col_idx == 0:
                continue
            
            
            for col_idx_comp, str_tuple_comp in enumerate(experiment):
                if col_idx == col_idx_comp:
                    continue                
                # if the comp invariant succeeded with a time below average and if the invariant was faster than the comp invariant
                if (re.match(r'\([a-zA-Z0-9]+,', str_tuple_comp).group(0)[1:-1] == 'Infinite') and (average_time_on_success[header[col_idx_comp]] > float(re.search(r' [0-9]+.[0-9]+\)', str_tuple_comp).group(0)[1:-1])):
                        if float(re.search(r' [0-9]+.[0-9]+\)', str_tuple_comp).group(0)[1:-1]) > float(re.search(r' [0-9]+.[0-9]+\)', str_tuple).group(0)[1:-1]):
                            influence_points[header[col_idx_comp]][header[col_idx]] += 1    
                            influence_time_benefited[header[col_idx_comp]][header[col_idx]] += (average_time_on_success[header[col_idx_comp]] - float(re.search(r' [0-9]+.[0-9]+\)', str_tuple_comp).group(0)[1:-1]))
                            influenced_others_points[header[col_idx]] += 1
                            if col_idx_comp == 0:
                                influenced_result_time_saved[header[col_idx]] += (average_time_on_success[header[col_idx_comp]] - float(re.search(r' [0-9]+.[0-9]+\)', str_tuple_comp).group(0)[1:-1]))
                            else:
                                influenced_others_time_saved[header[col_idx]] += (average_time_on_success[header[col_idx_comp]] - float(re.search(r' [0-9]+.[0-9]+\)', str_tuple_comp).group(0)[1:-1]))
            
    
    formatting1 = list()
    formatting1.append("INFLUENCE POINT RANKINGS:")
    results.append(formatting1)
    
    for idx, invariant in enumerate(header):
        
        #sort influence point list so that it ranks the most influential invariants for every other invariant based on amount of influence
        dummy = list()
        dummy.append(invariant + " was influenced by (descending order):")
        sorted_influence = sorted(influence_points[invariant].items(), key = lambda kv: kv[1], reverse=True)
        dummy.extend(sorted_influence) #adds influence point ranking
        
        #sort influence time saved list so that it ranks the most influential invariants for every other invariant based on time saved
        dummy2 = list()
        dummy2.append(invariant + " saved this much time from:")
        sorted_influence_time = sorted(influence_time_benefited[invariant].items(), key = lambda kv: kv[1], reverse=True)
        dummy2.extend(sorted_influence_time) #adds influence point ranking
        
        results[idx].append(influenced_others_points[invariant])
        results[idx].append(influenced_others_time_saved[invariant])
        results[idx].append(influenced_result_time_saved[invariant])
        
        results.append(dummy)
        secondary_results.append(dummy2)
        
    #extend results list by adding secondary_results as well.
    
    formatting2 = list()
    formatting2.append("INFLUENCE TIME BENEFIT RANKINGS:")
    results.append(formatting2)
    
    results.extend(secondary_results)
    
        
    
    new_header = ["Name", "Success Points", "Presence Points", "Success not Sufficient Points", "Average Time on Success", "Success Chance", "Influenced others", "Influence impact (seconds)", "Time saved for result assertion"]
    
    with open(output_file, 'w', newline='') as output_file:
        writer = csv.writer(output_file)
        writer.writerow(new_header)
        writer.writerows(results)



if __name__ == '__main__':
    
    # if a master csv has already been created and can be used instead of the raw data, set this to true.
    use_master_csv_flag = False    
    
    # Define the directory with the CSV files, output path, and the names file
    script_dir = os.path.dirname(os.path.realpath(__file__))
    output_file =  os.path.join(script_dir, '../master_evaluated.csv') # Replace with the actual output file name of the evaluation
    input_dir =  os.path.join(script_dir, '../out_files')  # Replace with the actual input directory path
    names_file =  os.path.join(script_dir, '../out_files/invariant_names.txt')  # Replace with the actual names file
    master_csv =  os.path.join(script_dir, '../master_condensed.csv')  # Path for the condensed data csv (master csv)

    if use_master_csv_flag == False:
        # Create the master CSV file
        create_master_csv(master_csv, input_dir, names_file)

        print(f"Master CSV created at {master_csv}")
    # Create the master CSV file
    process_csv(master_csv, output_file)

    print(f"Data has been processed: {output_file}")