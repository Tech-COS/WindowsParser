# POC for COS

## Commit Guide

This section was made to describe the commit guide of the COS Project.

1. Open a Github Issue.
	1. Name it appropriately.
  	2. Create a new branch using the Development panel on the right.
  	3. Check on which branch this new branch is based on by clicking on "Change branch source" and set it to "dev" if it isn't the one selected by default.

2. Once all changes have been made to one's local branch, write a commit using the following template:  
   [\#number] OPERATION: Description.

   **\#number HAS TO be the same as the issue.**  
   Example: [\#1] ADD: Adding testing binaries.  
   Once done, the changes can be pushed to the branch.

3. Create a pull request.
	1. Check that the merge is made TO "dev" FROM "branch".
	2. Name the pull request using the following template: [\#number] Name.  
           The number HAS TO be the same as the commit issue number for traceability.

4. Wait for collaborators to review the changes.  
   The merge has to be made by reviewers.

5. Repeat as needed.
