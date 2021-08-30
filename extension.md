# Reason for extension request:

In order to verify whether the constructed risk model can properly score risks for software projects, the idea was to use historical dependency update data with the underlying assumption that dependencies with vulnerabilities which pose a high risk to a software project are updated earlier with respect to the fixed version release date than dependencies which do not pose (such a high) risk for that project.

If that were the case, high risk scores from the risk model should correspond to swift updates, and vice versa.
However, current analysis seems to disprove the original assumption that higher risk dependencies are updated earlier, from the very weak correlation between CVSS scores and update delays.

## New plan

In the last meeting with Andy & Sebastian I had discussed these findings and then discussed a plan to arrive at a state which would warrant a 'green light'. That plan was to use the analysis method in combination with contacting committers / project maintainers of vulnerable (as shown by the call-graph and function level vulnerability information) repositories and ask about their update strategy, whether they knew they were impacted by the vulnerability and why they updated when they did (i.e. routine/updated due to risk/update for features in new version etc.). The goal from this analysis would then be to find the key properties to distinguish why vulnerable dependencies are updated at the date/time they are (i.e. investigating the original assumption for the risk model evaulation method in greater depth).

After some reading into how such an analysis would look it seems it has mostly already been researched by Paschenko et al. (https://dl.acm.org/doi/abs/10.1145/3372297.3417232) with as key difference that I would be able to use the FASTEN knowledge base to specifically target developers with projects actually at risk of the disclosed vulnerabilities.

Whereas Andy & Sebastian were in that plan focussed on this qualitative vulnerability update analysis approach which would likely drop the risk model from my thesis.
After meeting with Miroslav last week, it would seem a good idea to wrap up the risk model (we still had a few ideas which would be fairly quick to implement) and then still include it with a more small scale evaluation which would be focussed on investigating the several properties of the risk model on fairly small call-graphs (somewhere in the 20-60 nodes range).
As well as using the vulnerability history repository scanner for the orginal evaluation method on large, well-maintained java libraries (Dom4j, guava, etc.) with the idea that those would have a more sophisticated process in place and are actively maintained enough so that the original hypothesis that high risk vulnerable dependencies are updated quickly holds.

The final plan will likely be a combination of the more in-depth analysis in vulnerability history analysis, as well as wrapping up the risk model in combination with evaluating it by its properties on a smaller scale.

This Friday there will be another progress meeting with Miroslav & Sebastian to finalise & further clarify this plan.
