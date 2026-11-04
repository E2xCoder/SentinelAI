"""Cross-alert correlation: group related alerts into multi-stage incidents.

``correlate`` links alerts that share an entity (IP, user, host) within a
time window, orders them along the MITRE kill chain and scores the
resulting incident. Output is advisory and fully deterministic.
"""
