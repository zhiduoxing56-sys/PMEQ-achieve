//go:build phase6native

package discovery_test

import (
    "context"
    "encoding/csv"
    "encoding/json"
    "os"
    "path/filepath"
    "pmeq/internal/anchorfilter"
    "pmeq/internal/discovery"
    "pmeq/internal/scmpnative"
    "reflect"
    "runtime"
    "sort"
    "strconv"
    "testing"
)

type thresholdFullSet struct {
    Label string `json:"label"`
    OriginalQueryCount int `json:"original_query_count"`
    QueryCount int `json:"query_count"`
    Q int `json:"q"`
    BucketBits int `json:"bucket_bits"`
    Queries []thresholdOriginalQuery `json:"queries"`
}

type thresholdFullCase struct {
    ID int
    Side string
    Tau int
    Item thresholdOriginalQuery
}

func thresholdFullSelection(t *testing.T, f *fixture) (thresholdFullSet, thresholdFullSet) {
    t.Helper()
    a := thresholdFullSet{Label: "AnchorThresholdSet", OriginalQueryCount: 854, Q: 4, BucketBits: 16}
    g := thresholdFullSet{Label: "TargetThresholdSet", OriginalQueryCount: 854, Q: 4, BucketBits: 16}
    legal := 0
    seen := map[int]bool{}
    for _, w := range f.trace {
        valid := discovery.Validate(discovery.Query{Anchor:w.Anchor, Target:w.Target, TauAnchor:w.Tau, TauTarget:w.Tau}) == nil
        if valid == f.ref[w.Query].Rejected { t.Fatalf("original legality mismatch query=%d", w.Query) }
        if !valid { continue }
        legal++
        if seen[w.Query] { t.Fatalf("duplicate original query id %d", w.Query) }
        seen[w.Query] = true
        ra, rg := len(anchorfilter.QueryChunks(w.Anchor)), len(anchorfilter.QueryChunks(w.Target))
        item := thresholdOriginalQuery{w.Query, w.Anchor, w.Target, w.Tau, ra, rg}
        if ra >= 4 && rg >= 2 {
            for tau := 0; tau <= 3; tau++ {
                if discovery.Validate(discovery.Query{Anchor:w.Anchor, Target:w.Target, TauAnchor:tau, TauTarget:1}) != nil { t.Fatalf("invalid anchor full query %d tau %d", w.Query, tau) }
            }
            a.Queries = append(a.Queries, item)
        }
        if rg >= 4 && ra >= 2 {
            for tau := 0; tau <= 3; tau++ {
                if discovery.Validate(discovery.Query{Anchor:w.Anchor, Target:w.Target, TauAnchor:1, TauTarget:tau}) != nil { t.Fatalf("invalid target full query %d tau %d", w.Query, tau) }
            }
            g.Queries = append(g.Queries, item)
        }
    }
    if legal != 854 { t.Fatalf("original legal query count %d", legal) }
    sort.Slice(a.Queries, func(i,j int)bool{return a.Queries[i].QueryID<a.Queries[j].QueryID})
    sort.Slice(g.Queries, func(i,j int)bool{return g.Queries[i].QueryID<g.Queries[j].QueryID})
    a.QueryCount, g.QueryCount = len(a.Queries), len(g.Queries)
    return a,g
}

func TestThresholdFullFinalCandidateDiscovery(t *testing.T) {
    out := os.Getenv("PMEQ_THRESHOLD_FULL_OUTPUT")
    root := os.Getenv("PMEQ_THRESHOLD_FULL_ROOT")
    if out == "" || root == "" { t.Skip("requires explicit full threshold output and query sets") }
    shardCount, e := strconv.Atoi(os.Getenv("PMEQ_THRESHOLD_FULL_SHARD_COUNT")); must(t,e)
    shardIndex, e := strconv.Atoi(os.Getenv("PMEQ_THRESHOLD_FULL_SHARD_INDEX")); must(t,e)
    if shardCount < 1 || shardIndex < 0 || shardIndex >= shardCount { t.Fatal("invalid shard") }
    f := loadFixture(t)
    if len(f.areas) != 120071 { t.Fatal("not full database") }
    anchor, target := thresholdFullSelection(t,f)
    for _, saved := range []struct{name string; expected thresholdFullSet}{{"anchor-query-set.json",anchor},{"target-query-set.json",target}} {
        b,e := os.ReadFile(filepath.Join(root,saved.name)); must(t,e)
        var got thresholdFullSet
        must(t,json.Unmarshal(b,&got))
        if !reflect.DeepEqual(got,saved.expected) { t.Fatalf("saved set mismatch: %s",saved.name) }
    }
    var cases []thresholdFullCase
    for _, side := range []struct{name string; set thresholdFullSet}{{"anchor",anchor},{"target",target}} {
        for _, item := range side.set.Queries {
            for tau:=0; tau<=3; tau++ { cases=append(cases,thresholdFullCase{len(cases),side.name,tau,item}) }
        }
    }
    groups := map[int][]thresholdFullCase{}
    ids := []int{}
    for _, c := range cases {
        if c.Item.QueryID%shardCount != shardIndex { continue }
        if _,ok := groups[c.Item.QueryID]; !ok { ids=append(ids,c.Item.QueryID) }
        groups[c.Item.QueryID]=append(groups[c.Item.QueryID],c)
    }
    sort.Ints(ids)
    raw,e := os.OpenFile(filepath.Join(out,"candidate-raw.csv"),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600); must(t,e); defer raw.Close()
    w:=csv.NewWriter(raw)
    must(t,w.Write([]string{"case_id","query_id","variation_side","anchor_r","target_r","anchor_tau","target_tau","trial","candidate_discovery_ns","candidate_discovery_ms","online_bytes","user_to_cloud_bytes","cs_to_cs_bytes","cloud_to_user_bytes","K","route_count","groups","target_slots","candidate_pair_count","oracle_pairs","missing_candidate","extra_candidate","duplicate_candidate","wrong_anchor_id","wrong_target_id","pair_sha256","packet_id_sha256"}))
    checks,e := os.OpenFile(filepath.Join(out,"correctness.csv"),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600); must(t,e); defer checks.Close()
    cw:=csv.NewWriter(checks)
    must(t,cw.Write([]string{"case_id","query_id","variation_side","anchor_r","target_r","anchor_tau","target_tau","oracle_pairs","trial1_pairs","trial2_pairs","trial3_pairs","all_three_equal_oracle","missing_candidate","extra_candidate","duplicate_candidate","wrong_anchor_id","wrong_target_id","oracle_pair_sha256"}))
    packetIDs:=map[string]bool{}
    completed:=0
    for _,id:=range ids {
        selected:=groups[id]
        item:=selected[0].Item
        statics,buckets:=f.prepareStatic(t,workload{Anchor:item.Anchor,Target:item.Target,Tau:1})
        capacities:=map[int]candidateCapacity{}
        for _,c:=range selected {
            at:=1; if c.Side=="anchor" { at=c.Tau }
            if _,ok:=capacities[at];!ok {
                capacities[at]=thresholdCapacity(t,f,discovery.Query{Anchor:item.Anchor,Target:item.Target,TauAnchor:at,TauTarget:1},buckets)
            }
        }
        for _,c:=range selected {
            at,gt:=1,1
            if c.Side=="anchor" {at=c.Tau} else {gt=c.Tau}
            q:=discovery.Query{Anchor:item.Anchor,Target:item.Target,TauAnchor:at,TauTarget:gt}
            if discovery.Validate(q)!=nil { t.Fatalf("illegal case %d",c.ID) }
            want:=thresholdOracle(f,q)
            wantPairs:=dbSortedPairs(want)
            wantHash:=candidatePairHash(wantPairs)
            cap:=capacities[at]
            counts:=[3]int{}
            for trial:=1;trial<=3;trial++ {
                u,p0,p1,_,e:=discovery.Provision(statics[0],statics[1],cap.buckets,cap.capacities,cap.shape,scmpnative.Backend{});must(t,e)
                packetHash:=formalPacketID(u)
                if packetIDs[packetHash] {t.Fatal("reused one-time packet",c.ID,trial)}
                packetIDs[packetHash]=true
                got,m,e:=discovery.RunLocal(context.Background(),q,f.keys,u,statics,[2]*discovery.PartyPacket{p0,p1},scmpnative.Backend{});must(t,e)
                errors,recovered:=formalErrors(want,got.Pairs)
                if errors!=(dbErrors{}) || len(got.Pairs)!=len(wantPairs) || candidatePairHash(recovered)!=wantHash {t.Fatalf("plaintext mismatch case=%d trial=%d errors=%+v",c.ID,trial,errors)}
                if m.K!=cap.shape.K || m.Routes!=cap.shape.K*cap.shape.R || m.Groups!=cap.shape.G || m.Slots!=cap.shape.S || m.Cloud<=0 || m.Recovery<=0 || m.Token<=0 {t.Fatalf("workload/timer mismatch case=%d trial=%d",c.ID,trial)}
                user:=m.UserToCloud[0]+m.UserToCloud[1]
                cloud:=m.CloudToUser[0]+m.CloudToUser[1]
                online:=user+m.ServerBytes+cloud
                counts[trial-1]=len(got.Pairs)
                ns:=(m.Cloud+m.Recovery).Nanoseconds()
                record:=[]string{strconv.Itoa(c.ID),strconv.Itoa(item.QueryID),c.Side,strconv.Itoa(item.AnchorSignatures),strconv.Itoa(item.TargetSignatures),strconv.Itoa(at),strconv.Itoa(gt),strconv.Itoa(trial),strconv.FormatInt(ns,10),strconv.FormatFloat(float64(ns)/1e6,'f',6,64),strconv.FormatUint(online,10),strconv.FormatUint(user,10),strconv.FormatUint(m.ServerBytes,10),strconv.FormatUint(cloud,10),strconv.Itoa(m.K),strconv.Itoa(m.Routes),strconv.Itoa(m.Groups),strconv.Itoa(m.Slots),strconv.Itoa(len(got.Pairs)),strconv.Itoa(len(wantPairs)),"0","0","0","0","0",wantHash,packetHash}
                must(t,w.Write(record));w.Flush();must(t,w.Error())
            }
            correct:=[]string{strconv.Itoa(c.ID),strconv.Itoa(item.QueryID),c.Side,strconv.Itoa(item.AnchorSignatures),strconv.Itoa(item.TargetSignatures),strconv.Itoa(at),strconv.Itoa(gt),strconv.Itoa(len(wantPairs)),strconv.Itoa(counts[0]),strconv.Itoa(counts[1]),strconv.Itoa(counts[2]),"true","0","0","0","0","0",wantHash}
            must(t,cw.Write(correct));cw.Flush();must(t,cw.Error())
            completed++
            if completed%10==0 {t.Logf("THRESHOLD FULL shard=%d/%d progress=%d",shardIndex,shardCount,completed)}
        }
        statics=[2]*discovery.Static{}
        runtime.GC()
    }
    t.Logf("THRESHOLD FULL shard=%d/%d complete cases=%d trials=%d",shardIndex,shardCount,completed,3*completed)
}
