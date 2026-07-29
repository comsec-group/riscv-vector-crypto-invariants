# Leveraging Invariants for Scalable Verification of RISC-V Cryptography Extensions

by Kim Fahrni, Katharina Ceesay-Seitz, Denis Zuppiger and Kaveh Razavi

## Abstract
RISC-V has recently ratified a vector cryptography extension. Ex-
haustive formal verification of hardware designs that implement
this extension is crucial for security. However, scaling verification
for designs with such large bit-widths is challenging. We present
the first formal verification of Marian, an open-source implementa-
tion of the RISC-V vector cryptography extensions. We show that
proof modularization enables us to obtain an unbounded proof
for Marian. Together with our systematic invariant identification,
we reach a speedup of 2.7×. Our evaluation shows that invariants
that assert properties of counters, such as bounds or directions, or
handshakes are particularly effective in improving the verification
times. We show the generalizability and reusability of our invariant
identification methodology by formally verifying another custom
implementation of RISC-V vector cryptography extensions. During
verification, we found a violation that turned out to be a flaw in the
specification, which is now being updated.

[LINK](https://comsec.ethz.ch/research/hardware-design-security/leveraging-invariants-for-scalable-verification-of-risc-v-cryptography-extensions/)


# Evaluation Scripts for Invariant categorization

## Contents of the repository:
- /scripts contains the python scripts that automatically evaluate the performance of invariants using a formal verification tool, according to the contents of our paper.
- /marian_changes contains the modifications we made to the crypto unit to read out intermediate values easier.
- /c_model contains the code we took directly from [spike](https://github.com/riscv-software-src/riscv-isa-sim) with comments for formal verification adaptation.
- bender_script_marian and marian_cryptu_unit_example.tcl can be used to set up formal verification on Marian. Due to licencing and proprietary tool commands, these files are not usable out of the box, but contain instructions on how to adapt them for use.
- marian_cryptu_unit_example.tcl also contains the invariants we used for Marian and disccussed in our paper.

#### Notes on the use of scripts
All scripts we provide here were tested using Jasper gold, version 24.09.000. And Python 3.6.8. We can not guarantee functionality for other versions or tools, but have tired to make the scripts easily adaptible.

Both scripts that start the testruns have a variable called *tool_startup_command* which **HAS** to be defined by the user according to their tool, as the scripts otherwise will not function.

The tools also contain instructions that generate reports in the form of csv files. These instructions have to be adjusted if a different tool is used, and the formatting should be kept to one that then can be correctly interpreted by the script. 

#### TCL required for these scripts
The TCL scripts that should be prepared for optimal use of these evaluation scripts are the original script, called *orig_script* in the python files and declared with SCRIPTNAME.tcl by default. To ensure this file works properly, it should follow rough formatting explained further down this README. Additionally, a copy of the file that is stripped of all invariant assertions but otherwise identical should be provided, called *working_script* in the python files and declared with STRPPED_SCRIPT.tcl by default.

The reason for this is that the *orig_script* will only be read from, while the *working_script* will be read from and written to during the runtime of the scripts, and modified wiht the different invariant permutations.

If demand exists, as further steps the authors can automate the generation of the *working_script* so that only the *orig_script* has to be provided, but that is currently not implemented.

#### Notes on included TCL
Due to licencing we will currently not provide any other verification scripts that we used, but we are available per email (refer to the paper linked above) for further details on use and functionality of this work.

## Evaluation scripts:
There are two toolchains to evaluate the impact of invariants. both require a tcl script (or similar script of your choice) that contains one result assertion and multiple helper assertions (noted in the example script with assert -helper {[INVARIANT]}).

The assertions have to be named, and the helper invariants have to be grouped in any number of groups, going from 1 to group_count by ending their name with _g[group_number]. for example group one would be -name invariant_assertion_g1. No leading zeroes are required. Invariant assertions by default also have to be declared using the syntax described above (assert -helper {[INVARIANT]}). This can be adjusted depending on the syntax of commands for the tool of your choice, but will also have to be changed in the parser part of the scripts in that case.

If an advanced testrun is performed, a template in ./scripts/tcl_template.txt can be used, the first part of which configures Jasper and the engines that will be used, and can be edited to fit the tool and configuration that fits your needs. In the case of an advanced testrun, the tcl script that is used as a basis should NOT contain a prove statement as the script will insert it. The advanced testrun script also sets up logging relevant to the advanced testruns, which should be adapted to the tool of your choice if not using Jasper.

For a regular testrun, the tcl script should contain a prove statement already, as there is no need for a template to set up the advanced logging and we will not need to insert a prove statement through the script.

#### Which script to use when?
The regular testrun will not perform detailed logging and is useful for figuring out which invariants make an impact on a verification that already manages to find a proof within the defined time limit. The results from the regular testrun can be used to optimize the required invariants, exclude unnecessary ones and assist in defining a targeted approach for further invariant search. Choose the regular testrun if your result assertion finds a proof when all helpers are active and most or all helper assertions reach a proof as well in that scenario.

The advanced testrun performs more detailed logging and analysis in cases where the proof bound is more relevant and an unbounded proof can not be reached yet, but invariants already have an impact on performance on the proof. The results from the advanced testrun can be used to identify which invariants give the biggest improvement to the bound of the result, which invariants impact the performance of other invariants and which invariants are not impactful or even detrimental to the performance. The results can also be useful to identify a direction of search and impactful areas of the design for a guided approach toward the identification of further invariants.
Choose the advanced testrun, if your result assertion does not reach a proof, but at least some of the helper assertions do, and there is a noteable difference in the bound between using the helpers and not.


### Regular Testrun

This requires the files ./scripts/testruns.py and ./scripts/test_analyzer.py.

First, configure the testrun parameters within ./scripts/testruns.py at the start of the script:

- orig_script: The .tcl script to be used as the basis, containing all of the assumptions
- working_script: The location and name of the temporary script that will be created to run the experiments
- out_dir: The directory where the raw data of the experiments will be saved.
- invariant_names: The name of the file that defines the invariant names. DOES NOT NEED TO BE CHANGED.
- group_count: Amount of groups that are defined in the .tcl script, indexing starts at 1 and goes up to group_count.
- runs_per_permutation: how many times every permutation should be run. default is 1, but can be any number. This directly multiplies the amount of time all testruns will take.
- time_per_run: how long one experiment should last for, after this time the proof attempt will be terminated, a report generated and the next experiment will start. IN SECONDS
- result_assertion_name: name of the result assertion that should be evaluated, has to be the same as in the tcl script. RESULT ASSERTION SHOULD NOT BE PUT IN A GROUP.
- use_assumptions: this flag changes all helepr assertions to be assumptions instead for the testruns, to evaluate pure impact on the result speed without the helpers needing to reach a proof themselves every time. THIS IS EXPERIMENTAL. using this flag results in output files that can not be correctly analyzed by the test_analyzer. Implementing an analyzer for this data has yet to be done.


The testruns will last for (time_per_run + [time to analyze and evaluate design])\*(runs_per_permutation\*(2^group_count - 1)) seconds.

For example, with a compilation time of 20 seconds, a runtime of 180 seconds, 1 run per permutation and 10 groups, the entire script will run for 204'600 seconds, or 2 days 8 hours and 50 minutes.

We reccommend running the entire script in a tmux session or similar environment due to the long runtime.

### Evaluation of regular testrun

After the testruns are done, the results can be evaluated with the test_analyzer.py script. To do this, simply change the relevant file and directory names at the bottom of the script and then let it run. The resulting table evaluates the 10 metrics defined in my thesis, where I also explain in detail what each of the metrics means.

#### Metric Description
- ***Success Points*** Invariant assertion and result assertion reached proof
- ***Presence Points*** Invariant assertion did not prove but result did
- ***Success insufficient*** Invariant assertion reached proof but result did not
- ***Average time on success*** Average time to infinity bound proof for invariant assertion
- ***Success Chance*** Ratio of invariant assertion reaching proof (not related to
success of result assertion)
- ***Influenced others*** How many other assertions were positively impacted in speed
by this assertion
- ***Influence impact*** How much time other assertions saved in total whenever this
assertion was active
- ***Time saved on result*** How much time the result assertion saved in total whenever
this assertion was active and the result assertion reached a
proof faster than average
- ***Influence Points*** What other assertions accelerated the proof speed of this as-
sertion the most often (ordered list)
- ***Influence time benefited*** What other assertion saved this assertion the most time when
they proved first, ranked by total time saved (ordered list)

### Advanced Testrun

This requires the files ./scripts/advanced_testruns.py and ./scripts/advanced_test_analyzer.py.

First, configure the testrun parameters within ./scripts/advanced_testruns.py at the start of the script:

- logs_dir: directory where all reports and raw data is saved to for processing
- orig_script: location and name of the tcl script to be used as a basis for the experiments
- working_script: location and name of the temporary script generated and used by these experiments
- prove_config_template: location of the template used for the proof. first part of the template can be edited to change the configuration for Jaspers engines. second part should not be edited.  DOES NOT NEED TO BE CHANGED
- project_dir: directory for all jgproject folders. DOES NOT NEED TO BE CHANGED
- out_dir: directory for all reports.  DOES NOT NEED TO BE CHANGED
- invariant_names: name of the file containing all invariant names. DOES NOT NEED TO BE CHANGED
- test_name: name to use for logfiles
- group_count: Amount of invariant groups used, groups are indexed starting at 1 going up to group_count.
- runs_per_permutation: Amount of runs for a single experiment, default should be 1, on higher count takes average of multiple runs.
- time_per_run: time IN MILISECONDS that one experiment will take.
- result_assertion_name: name defined for the result assertion.
- use_assumptions: this flag changes all helepr assertions to be assumptions instead for the testruns, to evaluate pure impact on the result speed without the helpers needing to reach a proof themselves every time. THIS IS EXPERIMENTAL. using this flag results in output files that can not be correctly analyzed by the test_analyzer. Implementing an analyzer for this data has yet to be done.
- logging_interval: interval of regular logging IN MILISECONDS, default is 10000
- rapidfire_loggin_interval: interval of rapidfire logging IN MILISECONDS, default is 100 (rapidifire logging logs at that interval until first regular logging interval is reached)
- continue_previous_attempt: if this is True, the script will only continue from the point that it previously left off, based on existing logs in out_dir. If false, it starts at the beginning.

We reccommend running the entire script in a tmux session or similar environment due to the long runtime.


### Evaluation of advanced testruns

After the advanced testruns are done, the results can be evaluated with the advanced_test_analyzer.py script. To do this, simply change the relevant file and directory names at the bottom of the script, as well as any parameters so they are the same as the parameters used in the experimenst that are to be evaluated and then let it run. The resulting table evaluates the advanced metrics defined in my thesis, where I also explain in detail what each of the metrics means.

#### Metric Description
- ***Success Chance*** Ratio of invariant assertion reaching proof (not related to
success of result assertion)
- ***Average time on proof*** Average time to infinity bound proof for assertion
- ***Average bound on fail*** Average bound that was reached when no proof was found
for assertion
- ***Average time to bound on fail*** Average time that highest bound that attempt was reached
- ***Fastest time for highest bound*** Highest bound reached with corresponding fastest time and
experiment number
- ***Part of best result*** Whether this invariant assertion was active in the experi-
ment where the result assertion reached its highest bound
the fastest
- ***Influence on proof*** Amount of times another assertion proved while this one was
active
- ***Influence on time to proof*** How much time other assertions saved when reaching a proof
while this one was active
- ***Influence on bound*** Amount of times another assertion reached a higher bound
than average while this one was active
- ***Influence benefited to proof time*** What other assertions accelerated the proof speed of this as-
sertion the most (ordered list)
- ***Influence benefited to bound*** What other assertions increased the bound of this assertion
the most (ordered list)



*Disclaimer: Currently, both testrun scripts will evaluate and analyze the design from scratch for every testrun, to ensure that all testruns have the exact same intial conditions and no cached data can impact the performance of testruns. If the scripts are used on an implementation where the time to analyze and evaluate is significant, compared to the duration of a single experiment that is being set, then the tcl scripts used as a basis for the evaluation should be adapted to load an existing design template instead of performing evaluation and analysis every time.*

