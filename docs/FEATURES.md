# Feature definitions

These are newly implemented features. Their names and formulas cannot be attributed to the unavailable Team CSEUG49 code.

Notation: d = Flow Duration / 1,000,000 seconds; Fp/Bp = Total Fwd Packet / Total Bwd packets; Fb/Bb = Total Length of Fwd Packet / Total Length of Bwd Packet; P=Fp+Bp; Z=Fb+Bb. `ratio(a,b)` returns a/b when b is finite and positive, otherwise zero. Invalid numerators propagate NaN to train-median imputation. No target labels enter these calculations.

| Column | Formula | Units |
|---|---|---|
| eng_duration_seconds | max(Flow Duration,0)/1e6 | seconds |
| eng_total_packets | P | packets |
| eng_total_bytes | Z | bytes |
| eng_packets_per_second | P/max(d,1e-6) | packets/second |
| eng_bytes_per_second | Z/max(d,1e-6) | bytes/second |
| eng_forward_packet_fraction | ratio(Fp,P) | fraction |
| eng_backward_packet_fraction | ratio(Bp,P) | fraction |
| eng_forward_byte_fraction | ratio(Fb,Z) | fraction |
| eng_bytes_per_packet | ratio(Z,P) | bytes/packet |
| eng_fwd_bytes_per_packet | ratio(Fb,Fp) | bytes/packet |
| eng_bwd_bytes_per_packet | ratio(Bb,Bp) | bytes/packet |
| eng_packet_direction_imbalance | ratio(abs(Fp-Bp),P) | fraction |
| eng_byte_direction_imbalance | ratio(abs(Fb-Bb),Z) | fraction |
| eng_syn_per_packet | ratio(SYN Flag Count,P) | flags/packet |

The two engineered per-second rates and original `/s` columns are capped at training quantile 0.995. All features receive training-median imputation and training-fitted standardization, followed by fixed clipping to [-20,20]. Fractions are not independently clipped before standardization. Nonphysical source values remain a data-quality limitation rather than receiving undisclosed corrections.

## Earlier completed-flow context

At completion time t, grouping uses raw source IP only as an internal key. Statistics use retained sampled flows with completion times in [t-window,t), excluding the current flow and every other flow tied at t. All records tied at t are scored before any update to history. A flow's information becomes available at start timestamp plus its duration. Windows use seconds, regardless of pandas datetime storage unit.

| Column | Definition | Units / default |
|---|---|---|
| ctx_source_flows_60s | Number of earlier source flows in 60 seconds | count, 0 |
| ctx_source_flows_300s | Number of earlier source flows in 300 seconds | count, 0 |
| ctx_source_bytes_60s | Sum of earlier forward + backward bytes in 60 seconds | bytes, 0 |
| ctx_source_packets_60s | Sum of earlier forward + backward packets in 60 seconds | packets, 0 |
| ctx_source_mean_duration_60s | Mean duration of those earlier 60-second flows | seconds, 0 |
| ctx_seconds_since_previous | Time since the source's previous completed retained flow, capped at 300 | seconds, 300 for unseen source |
| ctx_source_unique_dst_ports_60s | Number of distinct destination ports in prior 60 seconds | count, 0 |
| ctx_source_same_destination_60s | Number of prior 60-second source flows sharing the current destination IP | count, 0 |

Missing previous-flow byte/packet/duration values contribute zero in the history accumulator. Raw source/destination IP values, source port, absolute time, true labels and attack identities are not model inputs. The history is a sampled-traffic observation process, and its density differs from the full capture. This is a limitation for deployment claims and a reason to replay the complete flow stream in later validation.
