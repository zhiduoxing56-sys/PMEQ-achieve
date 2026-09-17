# PHASE10B — Target aggregation and fixed-domain candidate pairs

AUTHORITATIVE REPO = `/home/tenggn/projects/clean_pmeq`.
Begin HEAD `33e0dd3`, clean. No alternate repository or backup was modified.
PHASE5 and original PSMJ remain sealed; bucket widths16/q4/tiers unchanged.

## Contract and sidecar audit

DTarget=26 for every Anchor candidate. Trusted DO assigns ascending numeric
alias-ID ranks within each join, including short strings. No actual nalias,
join value, or ordinal→ID map enters a cloud. Initial token validation requires
1<=r<=16 and 0<=tau<r,lambda=r-tau. Both threshold masks are prepared before the
initial query; clouds do not receive plaintext lambda.

The sidecar manifest binds original IndexID, original manifest-byte SHA256,
version1/Q4/width16/tiers through that sealed manifest, full ordered structure,
D26/multiplicity3, both sidecar hashes and lengths. Each party file is
PMEQTG01 + party + IndexID + manifest digest; then every bucket's ordered widths,
column-major incidence shares, group-major26 Ring64 payload shares. Group/slot
prefixes use PadWidth, never bucket.LPad. Both sidecar-generation hashes also
bind every online transcript. Load checks all 65536 buckets and pins the digest
to the exact manifest bytes actually loaded by PHASE8, before sidecar I/O.

Full raw audit: maximum aliases per join26, maximum group/record multiplicity3,
short Target rows4047. Build/order audit:65536 buckets,310331 groups,1317260
physical slots,480945 real slots,0 errors. Independent oracle reads ALL 34248760
coefficients and 8068606 payloads,0 errors; both parties exhibit all128 coefficient
marginals. Those tests supplement the independent-mask security argument.

| static field | bytes/party | both parties |
| --- | ---: | ---: |
| incidence,26×1317260 | 34,248,760 | 68,497,520 |
| Target ID,310331×26×8 | 64,548,848 | 129,097,696 |
| framing and ordered widths | 1,503,525 | 3,007,050 |
| complete sidecar | 100,301,133 | 200,602,266 |

Large sidecar binaries are local ignored artifacts; manifest and audit are
tracked. Original PSMJ/payload hashes were verified unchanged. The loader gets
only its own file and the trusted manifests, never a peer file.

## Algebra and output

F[c,h,u]=sum_s E_beta[u,s]*Hit[c,h,s] mod128; F<=3.
z=[F>=1]; C[c,u]=sum_h z[c,h,u]<=16; Keep=[C>=r-tau].
Hit/z conversions and64-posting scalar-vector incidence reuse the existing
clean primitives; comparisons use real LLAMA Bin7/Bout1 with rb removed.
No full26×S intermediate product array or global Target permutation exists.

ID_h[c,u]=sum_g Match[c,h,g]*Payload[g,u] in Ring64, using retained PHASE8 Match,
not rerun PE. Payload refers to ordinal u within that group's join even when
that alias lacks the group's qgram. Rep=z_h AND NOT(seen); seen XOR=rep, for
all r1..16. SelectedID=sum_h rep_h*ID_h. Final AnchorID=Keep*AnchorID[c] and
TargetID=Keep*SelectedID. Every conversion/multiplication uses fresh material.
Ring64 B2A is b0+b1-2*b0*b1, not reinterpretation of3x7-bit limb shares.

Output is CandidatePairShares{Manifest,LayoutID,CompactionID,QueryID,K,DTarget26,
PairKeepShares,AnchorIDShares,TargetIDShares}. All three arrays have26K entries,
candidate then ordinal order. Inactive IDs reconstruct to0. No second compaction,
final count opening, plaintext ID, or Query User recovery is implemented.

## Correctness scope

The approved replay policy preserves all 1003 historical queries/Tau values.
149 fail tau_target<r_target and are explicit aggregation rejection cases.
854 execute pair generation; rejected queries are NOT counted as zero-pair
answers. All1003 still execute actual Anchor filtering/aggregation/compaction,
routing, Target PE and Position:466105 routes,2209949 groups,9380900 slots.
Aggregation never consumes oracle-created Hit or Match.

The opt-in trusted phase10audit build checks every F,z,C,Keep,rep,SelectedID,
and both masked IDs. An independent raw-string qgram/position oracle checks the
final signature-filter candidate pair set, before any future full edit-distance
verification/retrieval. It is not a claim that full EJSM string verification is
implemented. False positives=0; false negatives=0; duplicate pairs=0;
wrong AnchorID=0; wrong TargetID=0, for all 854 accepted queries.

Synthetic and native boundaries cover K0/K1, r1/r16, lambda1/lambda-r, aliases0/1/26,
repeated occurrences, three postings per record, dummy/zero-hit records, high
Ring64 IDs/wraparound, one-use/reordered/misbound messages. Correctness audits
are separate from the single-party security review.

Accepted queries return 1,510 oracle pairs in total. Pair cardinalities below are TRUSTED TEST statistics only.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| oracle pairs (854 accepted) | 1.768150 | 0 | 2 | 6 | 15 | 667 |

## Workload sizes — all 1003 historical queries

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| K | 124.144566 | 5 | 151 | 431 | 2,843 | 4,780 |
| R | 2.626122 | 2 | 5 | 6 | 8 | 16 |
| G | 2,203.338983 | 49 | 1,908 | 5,745 | 50,754 | 180,227 |
| S | 9,352.841476 | 212 | 8,032 | 24,444 | 215,484 | 764,768 |
| routes K*r | 464.710867 | 10 | 404 | 1,215 | 10,644 | 38,240 |
| public domain26K | 3,227.758724 | 130 | 3,926 | 11,206 | 73,918 | 124,280 |

## Accepted workload and cost accounting —854 executed aggregation queries

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| K | 97.946136 | 4 | 84 | 349 | 2,739 | 4,780 |
| R | 2.841920 | 2 | 6 | 6 | 8 | 16 |
| G | 2,218.509368 | 41 | 1,549 | 4,950 | 52,760 | 180,227 |
| S | 9,417.381733 | 176 | 6,592 | 20,944 | 223,604 | 764,768 |

Let M=26K, Z=26Kr, S=physical slots and G=group comparisons.
All cost figures below combine BOTH parties unless explicitly per-party.

- Z128 one-time body=112S+6Z: Hit B2A6S, scalar-vector triples106S, z B2A6Z.
- SCMP body=572(Z+M):284-byte native key + cached rb1 + Z128 mask1 per party
  per comparison. Actual key byte lengths are counted during preprocessing.
- Ring64 body=48(27G+2Z+3M), fresh24-byte local triple shares per party.
- F2 representative body=6Z.
- Online masked body=58S+864G+74Z+98M. This uses scalar-vector incidence;
  historical scalar-per-coefficient estimates do not apply.
- Online framing=74*(9+B+H+r+ceil(Z/4096)), where B=sum_routes ceil(T/64),
  H=sum_routes ceil(groupCount/64). K0 sends no messages. Actual encoded outgoing
  lengths are measured, and unit tests cross-check the exact formula.
- Retained output fields=34M both/17M per party. Output write means descriptor
  transfer into the in-memory result; field writes occur in masking stages.
  There is no output network/disk serializer or recovery implementation.

Offline body excludes user mask metadata(two bytes), packet IDs/shape/lineage,
registries, slice headers and allocator overhead. It is not a wire codec or a
resident-memory claim. Offline K/S/G upper-capacity packets are supported for a chosen r class;
unused capacity burns. Reported experiments provision exact measured shapes.
No online refill is permitted. For a finite pool,
reserved body is the SUM of actual packet classes, not a percentile times Q_pool.
Static sidecars and retained output are NOT server-server traffic.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| offline correlated body bytes | 14,024,207.044496 | 293,448 | 10,157,208 | 31,885,064 | 341,238,672 | 1,084,295,888 |
| online encoded bytes | 3,682,390.538642 | 73,982 | 2,659,760 | 8,323,588 | 88,604,522 | 291,448,466 |
| retained output field bytes | 86,584.384075 | 3,536 | 74,256 | 308,516 | 2,421,276 | 4,225,520 |

## Actual replay component times, ms —854 heterogeneous queries

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| Hit B2A | 0.159972 | 0.011515 | 0.134743 | 0.374011 | 4.089878 | 13.822857 |
| Incidence / F | 3.851116 | 0.090075 | 3.114095 | 9.115100 | 94.073904 | 336.526849 |
| F→z | 17.370252 | 0.336228 | 12.424811 | 35.991558 | 497.724018 | 1,505.120218 |
| z B2A | 0.196559 | 0.010346 | 0.163896 | 0.468249 | 4.978231 | 16.732683 |
| C local sum | 0.025846 | 0.001560 | 0.021337 | 0.059069 | 0.623266 | 1.956179 |
| C→Keep | 3.777425 | 0.145925 | 3.144038 | 12.671869 | 114.602507 | 199.172728 |
| GroupMatch→Ring64 | 0.137671 | 0.011605 | 0.097201 | 0.277789 | 3.473796 | 18.316690 |
| Group Target ID selection | 4.350199 | 0.140266 | 3.749151 | 10.636439 | 89.373862 | 497.331170 |
| Representative recurrence | 0.373251 | 0.011386 | 0.263307 | 0.901037 | 8.381348 | 31.984759 |
| Representative→Ring64 | 0.629720 | 0.023249 | 0.507238 | 1.219681 | 20.233190 | 52.409040 |
| Across-occurrence ID selection | 0.585498 | 0.019411 | 0.355734 | 1.075794 | 20.247710 | 42.164898 |
| Keep→Ring64 | 0.149435 | 0.013910 | 0.109196 | 0.484929 | 4.396235 | 11.140756 |
| Anchor ID mask | 0.115555 | 0.010575 | 0.088095 | 0.360771 | 3.739318 | 6.540065 |
| Target ID mask | 0.111475 | 0.009774 | 0.080006 | 0.292129 | 3.530296 | 8.275153 |
| Output descriptor write | 0.000101 | 0.000093 | 0.000129 | 0.000154 | 0.000231 | 0.000406 |
| SUM OF MEASURED COMPONENTS | 31.834074 | 0.855873 | 25.644657 | 75.557647 | 846.763727 | 2,558.076498 |

These are actual summed local times for both clouds, excluding Exchange waits,
heap sampling in Exchange, trusted audit callbacks and offline provisioning.
They are heterogeneous workload statistics, not repeated-trial latency quantiles
or TCP/E2E. Concurrent benchmarks/race checks share the host.

## Representative native repeated measurements

The fixture builder reuses the existing PHASE9 saved-real-workload routing/PE
benchmark setup. The first four points are S p50/p95/p99/max within the 854
valid-threshold queries. The fifth is the actual workload nearest their mean S.
The p50 case was remeasured with unconditional start/end heap sampling and
replaces its earlier missing-heap measurement. Larger cases retain the final
representative run. Each listed point has its own complete fresh-packet trials. It evaluates real PE
and Position to produce the aggregation inputs; no oracle Hit is injected.
These component fixtures restore saved candidate payload associations in the
trusted harness, unlike the separate actual full-chain correctness replay.
Each repeated aggregation trial provisions fresh SCMP/Beaver material and masked
bounds. PE/Position input preparation and preprocessing are outside timings.
Each trial reconstructs the same masked pair output. No old5.659ms sample is reused.


S=176, K=1, r=8, tau=0; 10 warmups + 50 measured fresh packets. Times in ms.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| Hit B2A | 0.015594 | 0.012786 | 0.036404 | 0.078144 |
| Incidence / F | 0.095631 | 0.086940 | 0.171141 | 0.191728 |
| F→z | 0.378964 | 0.361121 | 0.513918 | 0.618045 |
| z B2A | 0.010753 | 0.008955 | 0.028643 | 0.036756 |
| C local sum | 0.001461 | 0.001304 | 0.002842 | 0.004642 |
| C→Keep | 0.048528 | 0.044837 | 0.070200 | 0.098200 |
| GroupMatch→Ring64 | 0.006877 | 0.006064 | 0.011411 | 0.028075 |
| Group Target ID selection | 0.104624 | 0.099401 | 0.137393 | 0.260146 |
| Representative recurrence | 0.014002 | 0.012802 | 0.018941 | 0.039998 |
| Representative→Ring64 | 0.021429 | 0.019329 | 0.033317 | 0.048958 |
| Across-occurrence ID selection | 0.018065 | 0.015644 | 0.032049 | 0.042502 |
| Keep→Ring64 | 0.003765 | 0.003230 | 0.007394 | 0.011984 |
| Anchor ID mask | 0.002844 | 0.002429 | 0.005472 | 0.007859 |
| Target ID mask | 0.003133 | 0.002352 | 0.007629 | 0.009610 |
| Output descriptor write | 0.000252 | 0.000221 | 0.000364 | 0.000535 |
| SUM OF MEASURED COMPONENTS | 0.725922 | 0.695864 | 1.027623 | 1.396369 |

Offline body both=232,904 bytes; online both=66,088 bytes; retained fields both=884 bytes.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| sampled heap bytes | 351,846,576.960000 | 351,844,032 | 351,866,344 | 351,867,304 | 351,867,320 | 351,867,320 |
| sampled heap delta bytes | 548,634.240000 | 548,144 | 549,440 | 549,488 | 549,776 | 549,776 |

S=20,944, K=259, r=4, tau=1; 10 warmups + 50 measured fresh packets. Times in ms.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| Hit B2A | 0.451315 | 0.440159 | 0.638748 | 0.690611 |
| Incidence / F | 11.506089 | 11.458696 | 12.688253 | 13.939460 |
| F→z | 49.229958 | 48.484840 | 56.562739 | 69.786372 |
| z B2A | 0.655249 | 0.628672 | 1.040009 | 1.213845 |
| C local sum | 0.060489 | 0.056581 | 0.074883 | 0.178948 |
| C→Keep | 12.390409 | 12.122968 | 14.281479 | 24.694604 |
| GroupMatch→Ring64 | 0.319441 | 0.295192 | 0.511161 | 0.624952 |
| Group Target ID selection | 13.609557 | 13.377151 | 14.752255 | 18.743023 |
| Representative recurrence | 1.165731 | 1.163121 | 1.429767 | 1.558819 |
| Representative→Ring64 | 1.534547 | 1.569292 | 1.860941 | 1.956469 |
| Across-occurrence ID selection | 1.452137 | 1.416070 | 1.960276 | 2.013436 |
| Keep→Ring64 | 0.501774 | 0.487768 | 0.734541 | 0.898305 |
| Anchor ID mask | 0.387511 | 0.345895 | 0.609318 | 0.767350 |
| Target ID mask | 0.282935 | 0.271319 | 0.374145 | 0.494708 |
| Output descriptor write | 0.000305 | 0.000241 | 0.000432 | 0.001822 |
| SUM OF MEASURED COMPONENTS | 93.547448 | 92.691563 | 105.597533 | 114.835383 |

Offline body both=31,853,592 bytes; online both=8,268,132 bytes; retained fields both=228,956 bytes.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| sampled heap bytes | 457,012,728 | 457,011,192 | 457,028,712 | 457,032,984 | 457,033,176 | 457,033,176 |
| sampled heap delta bytes | 71,599,309.120000 | 71,599,072 | 71,600,272 | 71,600,512 | 71,600,832 | 71,600,832 |

S=223,604, K=2774, r=4, tau=2; 10 warmups + 50 measured fresh packets. Times in ms.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| Hit B2A | 3.630974 | 3.593037 | 4.150946 | 4.299830 |
| Incidence / F | 109.891240 | 109.607275 | 122.399047 | 129.409797 |
| F→z | 490.835328 | 492.428146 | 548.143532 | 573.301461 |
| z B2A | 6.554561 | 6.288890 | 8.036143 | 16.987490 |
| C local sum | 0.536614 | 0.518188 | 0.739465 | 1.105613 |
| C→Keep | 124.279963 | 123.310121 | 136.444729 | 171.050680 |
| GroupMatch→Ring64 | 6.139393 | 5.850618 | 8.293572 | 8.383491 |
| Group Target ID selection | 94.543241 | 94.485429 | 106.886663 | 113.949402 |
| Representative recurrence | 11.002056 | 10.706707 | 13.053580 | 18.953139 |
| Representative→Ring64 | 36.492616 | 35.001218 | 55.534859 | 60.508394 |
| Across-occurrence ID selection | 24.858494 | 24.132641 | 33.028143 | 34.552663 |
| Keep→Ring64 | 6.979257 | 5.538737 | 13.261159 | 14.370913 |
| Anchor ID mask | 8.012926 | 7.835966 | 11.961526 | 13.761408 |
| Target ID mask | 6.664406 | 6.767519 | 10.377635 | 11.676553 |
| Output descriptor write | 0.000332 | 0.000321 | 0.000457 | 0.000482 |
| SUM OF MEASURED COMPONENTS | 930.421402 | 933.027187 | 1,018.178071 | 1,095.544227 |

Offline body both=341,238,672 bytes; online both=88,604,522 bytes; retained fields both=2,452,216 bytes.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| sampled heap bytes | 1,403,204,409.440000 | 1,404,560,600 | 1,411,226,000 | 1,415,547,208 | 1,415,630,968 | 1,415,630,968 |
| sampled heap delta bytes | 683,797,917.440000 | 685,169,200 | 691,810,032 | 696,160,400 | 696,235,280 | 696,235,280 |

S=764,768, K=4780, r=8, tau=5; 5 warmups + 20 measured fresh packets. Times in ms.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| Hit B2A | 14.243370 | 14.091930 | 16.422308 | 16.868503 |
| Incidence / F | 324.310889 | 320.914582 | 365.497592 | 366.748254 |
| F→z | 1,615.799598 | 1,613.872903 | 1,707.563448 | 1,765.304447 |
| z B2A | 20.529026 | 20.105128 | 23.019443 | 24.772949 |
| C local sum | 1.880320 | 1.857312 | 2.100656 | 2.311438 |
| C→Keep | 200.240237 | 199.000352 | 215.039763 | 227.215718 |
| GroupMatch→Ring64 | 19.956799 | 19.007788 | 24.251014 | 39.291897 |
| Group Target ID selection | 429.022406 | 429.431473 | 462.152684 | 516.896416 |
| Representative recurrence | 29.770338 | 28.764876 | 33.381629 | 43.217242 |
| Representative→Ring64 | 94.898880 | 92.106090 | 117.737740 | 140.464726 |
| Across-occurrence ID selection | 43.606563 | 42.784041 | 47.688227 | 55.245015 |
| Keep→Ring64 | 6.355174 | 5.912727 | 8.227720 | 10.514645 |
| Anchor ID mask | 9.361673 | 9.494426 | 11.477677 | 11.892139 |
| Target ID mask | 10.108706 | 9.687430 | 12.868847 | 13.988626 |
| Output descriptor write | 0.000524 | 0.000292 | 0.000400 | 0.004821 |
| SUM OF MEASURED COMPONENTS | 2,820.084502 | 2,806.194872 | 3,005.693758 | 3,014.625046 |

Offline body both=1,084,295,888 bytes; online both=291,448,466 bytes; retained fields both=4,225,520 bytes.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| sampled heap bytes | 2,974,592,396 | 2,973,557,240 | 2,983,622,392 | 2,983,622,856 | 2,983,623,384 | 2,983,623,384 |
| sampled heap delta bytes | 1,457,738,617.600000 | 1,456,703,312 | 1,466,761,248 | 1,466,761,952 | 1,466,762,528 | 1,466,762,528 |

S=9,440, K=161, r=3, tau=0; 10 warmups + 50 measured fresh packets. Times in ms.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| Hit B2A | 0.215791 | 0.206335 | 0.274390 | 0.342550 |
| Incidence / F | 4.499258 | 4.497757 | 4.984965 | 5.287861 |
| F→z | 20.136883 | 19.688108 | 22.427300 | 33.075625 |
| z B2A | 0.279720 | 0.252168 | 0.477456 | 0.770896 |
| C local sum | 0.032282 | 0.030379 | 0.039107 | 0.065207 |
| C→Keep | 6.769561 | 6.548659 | 8.223468 | 11.837043 |
| GroupMatch→Ring64 | 0.155201 | 0.128430 | 0.339033 | 0.540760 |
| Group Target ID selection | 5.570342 | 5.395865 | 6.829697 | 9.612085 |
| Representative recurrence | 0.448499 | 0.419797 | 0.572452 | 0.902362 |
| Representative→Ring64 | 0.697216 | 0.676461 | 0.900131 | 0.995058 |
| Across-occurrence ID selection | 0.557690 | 0.551316 | 0.690552 | 0.733929 |
| Keep→Ring64 | 0.235089 | 0.219373 | 0.378243 | 0.438137 |
| Anchor ID mask | 0.171903 | 0.164538 | 0.289418 | 0.294642 |
| Target ID mask | 0.151718 | 0.151494 | 0.185866 | 0.240832 |
| Output descriptor write | 0.000217 | 0.000198 | 0.000383 | 0.000403 |
| SUM OF MEASURED COMPONENTS | 39.921371 | 39.031168 | 43.508716 | 60.094622 |

Offline body both=15,493,048 bytes; online both=3,891,292 bytes; retained fields both=142,324 bytes.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| sampled heap bytes | 403,029,401.920000 | 403,030,304 | 403,048,272 | 403,050,864 | 403,051,824 | 403,051,824 |
| sampled heap delta bytes | 34,896,488.320000 | 34,896,416 | 34,897,376 | 34,897,728 | 34,898,992 | 34,898,992 |

## Memory

Replay coverage: 443 of854 queries had a frame above the sampling threshold. The remaining 411 are UNSAMPLED, not zero-heap observations. The following replay statistics cover only the sampled subset. Small and mean-workload representatives above use unconditional start/end sampling.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| sampled-subset heap bytes | 1,657,708,506.799097 | 1,565,450,992 | 2,092,357,824 | 2,308,263,040 | 5,336,078,344 | 6,752,811,656 |
| sampled-subset heap delta bytes | 45,971,670.284424 | 3,917,440 | 69,473,248 | 147,677,072 | 1,361,352,672 | 1,827,508,304 |

Heap is the dual-party trusted process, not per-cloud RSS. Baselines are sampled
post-preprocessing; repeated benchmarks additionally force GC before that sample.
Replay heap is sampled on masked frames larger than4096 bytes; supplemental
small/mean benchmarks also sample unconditionally before and after execution. Deltas can include GC
retention and upstream objects; they are sampled observations, not continuous
peak-live measurements. Incidence streams64 slots, group payload products64
groups, across-occurrence selection4096 fields; no 26×S product matrix exists.
Full F/z/ID occurrence vectors are bounded by26Kr; one-time material and static
sidecars are separately accounted. Peak RSS includes the upstream chain/oracle
and is not an incremental production-party footprint.


Full replay process:

```text
Elapsed (wall clock) time (h:mm:ss or m:ss): 24:19.24
Maximum resident set size (kbytes): 7089776
Swaps: 0
```


Repeated benchmark process:

```text
Elapsed (wall clock) time (h:mm:ss or m:ss): 8:40.34
Maximum resident set size (kbytes): 3516120
Swaps: 0
```


Supplemental small/mean benchmark process:

```text
Elapsed (wall clock) time (h:mm:ss or m:ss): 0:43.62
Maximum resident set size (kbytes): 2246644
Swaps: 0
```


## Historical comparison

Historical Villesse: K488,r3,116991 slots,p95 aggregation5.659ms is reference
only. It used a variable actual-nalias domain, preprocessing reused outside the
benchmark loop, no final Ring64 pair selection, a harness not demonstrating
production-party isolation, and different ID representation. Current measurements
use fixed26, fresh one-time packets, separate party-local Run calls and complete
Ring64 selection/masking. No numerical speedup against incompatible scopes is claimed.

## Single-party security audit

Production Run takes one sidecar, one Match/Hit set, one packet, masked threshold
and an Exchange accepting framed masked messages only. It has no raw DB, DO,
preprocessing, reconstruction, derivation-key, peer object or logging dependency.
Party state contains own dense coefficient/ID shares only. Runtime shapes depend
on existing K/r/bucket access/public widths and fixed26, never actual nalias or
secret predicates. All fields of zero are fresh masked shares. Packet copies
share one claim guard, streamed ranges are disjoint, final ID masks refresh both
active and inactive outputs. Fresh SCMP/Beaver masks make each message simulatable
under the existing trusted-dealer/semi-honest noncolluding assumptions.

No cloud reconstructs posting→record mapping, nalias, joinID, Target ID,z,Keep,
representative or final pair count. Direct GroupMatch reuse never exposes Match.
Production output has exactly26K entries and no final count field. Privacy is
relative to existing public leakage, which can itself imply empty results. The normal
build has no audit sink; the phase10audit instrument is trusted test-only and
must not be deployed. Tests examine imports/calls, output schema, private party
fields, duplicate packets, frame binding, every static coefficient and native
algebra. Distribution/schema tests support, but do not replace, the masking
argument. No malicious-security or hidden-bucket-pattern claim is made.

## Validation and reproduction

All distribution quantiles use nearest rank (ceil(n*p)-1); means are arithmetic.
The final metadata-only hardening pins the sidecar to PHASE8's loaded manifest.
Its negative substitution test and positive full own-file load pass; final
ordinary/native/race/vet checks cover this guard. Saved full-chain/benchmark
measurements precede only this guard and used the same verified manifest bytes.

Run from `/home/tenggn/projects/clean_pmeq`. Go cache is writable under /tmp;
external unmodified LLAMA library is /tmp/phase6-native/libphase6scmp.a. The
current bridge invokes keyGenSCMP; initialization uses sysRandomSeed, not the
historical seeded benchmark wrappers. Source builds, if needed, use the existing
tools/build_phase6_native.sh and remain under /tmp.

```sh
GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test ./...
GOCACHE=/tmp/phase8-cache /tmp/go/bin/go vet ./...
GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test -race -timeout=60m ./...
PMEQ_AGG_FULL=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test -tags 'phase10integration phase9integration phase6native phase10audit' ./internal/aggregation -run '^TestReal1000Queries$' -count=1 -timeout=90m -v
PMEQ_TARGET_AGG_BENCH=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test -tags phase6native ./internal/targetposition -run '^TestPhase10NativeBenchmarks$' -count=1 -timeout=60m -v
PMEQ_TARGET_AGG_BENCH=1 PMEQ_TARGET_AGG_BENCH_SCOPE=small_mean CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test -tags phase6native ./internal/targetposition -run '^TestPhase10NativeBenchmarks$' -count=1 -timeout=30m -v
python3 tools/summarize_phase10b.py
```

Sidecar builder test is opt-in PMEQ_TARGET_SIDECARS=1 and uses exclusive-create
for artifact files to prevent silent replacement. Existing sidecars can be
independently re-audited with TestEverySidecarCoefficientAndPayload.
Final ordinary/native/race/vet/gofmt/diff and obsolete-path checks are recorded
in the companion validation logs and migration log.

Target Aggregation complete=YES; Candidate ID Generation complete=YES.
Final pair count opened to clouds=NO; Target IDs opened to clouds=NO.
Query User recovery started=no; short-string completeness=OPEN.
Query-time DO=no; paper modified=no; alternate repository created=NO;
obsolete repository used=NO; backup modified=NO.
