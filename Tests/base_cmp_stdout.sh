#!/bin/bash


# [ARRANGE]
# TODO consider `git branch --show-current` instead
# but requires newer git version AFAIK (on top of not working for submodules)
branch_to_test=$(git symbolic-ref --short HEAD)
test_output_file="./current.stdout.txt"
baseline_output_file="./baseline.stdout.txt"
# TODO parameterize the actual invocation that gets compared, either via config or cmd line args
# (consider directly controlling the invocation target(s) via pipeline vars once this runs as a proper CI job)
# (either directly inline via token replacement or via ENV vars set by the job which just get read by this script)
# (this way we wouldn't have to process command line args here and could still dynamically determine
# execution targets based on which analyzers were modified)
# (then the parts below would have to be looped for each module to be tested OR just loop the whole script instead?)
# TODO currently this only tests the linux analyzer

# [ACT]
echo "[INFO] Running a test analysis on the current branch and redirecting output to [${test_output_file}]"
python3 ./qu1cksc0pe.py --file /usr/bin/ls --analyze --no_banner > ${test_output_file}
echo "[INFO] Switching to master branch"
git checkout master
echo "[INFO] Running a test analysis on master for baseline output, redirecting to [${baseline_output_file}]"
python3 ./qu1cksc0pe.py --file /usr/bin/ls --analyze --no_banner > ${baseline_output_file}

# [ASSERT]
# TODO also diff any report files that might be present?
result=$(diff --text --ignore-all-space ${baseline_output_file} ${test_output_file})
if [ ${#result} -eq 0 ]
then
  echo "[INFO] test successful, found no diff!"
else
  echo "[FAILURE] the test output does NOT match the baseline:"
  echo "${result}"
  echo "[INFO] total diff size: ${#result}"
  exit 1
fi

# [CLEANUP]
echo "[INFO] Cleaning up test artifacts"
rm ${test_output_file}
rm ${baseline_output_file}
echo "[INFO] Switching back to branch: [${branch_to_test}]"
git checkout ${branch_to_test}


echo "[INFO] Here's git status:"
git status
