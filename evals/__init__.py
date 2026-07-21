"""AgentForge attack suite — reproducible eval cases run live against the target.

Case data lives under evals/cases/**/*.yaml; the loader/runner logic lives in
the installed agentforge package (agentforge.eval_case, agentforge.eval_runner)
so it is importable and unit-tested. `python -m evals.run` is the entrypoint.
"""
