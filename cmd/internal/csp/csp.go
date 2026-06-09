package csp

import (
	"fmt"
	"sort"

	"github.com/RoaringBitmap/roaring"
	"github.com/crillab/gophersat/maxsat"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"golang.org/x/exp/constraints"
)

// A set of subsets whose size is in the half-open range Bound. The Head
// indicates on which subset is being attempted as the current candidate
// solution. The combinadic can be used to fashion a subset according to the
// current head.
type Region struct {
	Index      [2]int          // spec, clause
	Compatible *roaring.Bitmap // indices of devices that we are compatible with
	Bound      Bound           // half-open range of subset sizes
	head       *head           // the current subset being attempted as a solution
}

type Bound struct {
	LowerInclusive int
	UpperExclusive int
}

func BoundExactly(k int) Bound {
	return Bound{
		LowerInclusive: k,
		UpperExclusive: k + 1,
	}
}

func BoundAtLeast(k int, n int) Bound {
	return Bound{
		LowerInclusive: k,
		UpperExclusive: n + 1,
	}
}

// but not none
func BoundAtMost(k int) Bound {
	return Bound{
		LowerInclusive: 1,
		UpperExclusive: k + 1,
	}
}

func (r Region) String() string {
	return fmt.Sprintf(
		"region{Index:%v, Compatible:%v, Bound:[%d,%d), Head:%v}",
		r.Index,
		r.Compatible,
		r.Bound.LowerInclusive,
		r.Bound.UpperExclusive,
		r.head,
	)
}

type head struct {
	n int // size of set of matches, i.e. region.Available
	k int // size of subset, within a region's bound
	m int // total size of set of subsets, i.e. len(matches) choose k
	i int // index of size k subset from lexicographically ordered set of subsets of matches
}

func (h head) String() string {
	return fmt.Sprintf("head{n:%d, k:%d, m:%d, i:%d}", h.n, h.k, h.m, h.i)
}

// NextHead returns the next head in the region, or (nil, false) if there are no
// more for the given. If false is returned then the region is exhausted. Whereas
func (r *Region) NextHead() *head {
	n := int(r.Compatible.Stats().Cardinality)
	if r.head == nil {
		// We start with the largest subset so as to search in an order
		// that maximizes the number of interfaces.
		k := r.Bound.UpperExclusive - 1
		m := Binom(n, k)
		r.head = &head{
			n: n,
			k: k,
			m: m,
			i: 0,
		}
		log.Trace().Msgf("initialized head: %v", r.head)
		return r.head
	}
	r.head.i++
	if r.head.i < r.head.m {
		return r.head
	}
	k := r.head.k - 1
	if k < r.Bound.LowerInclusive {
		return nil
	}
	m := Binom(n, k)
	r.head = &head{
		n: n,
		k: k,
		m: m,
		i: 0,
	}
	return r.head
}

// An Assignment represents a specific subset from a region, whose Index
// corresponds to the Index of a region.
type Assignment struct {
	Index [2]int
	Set   *roaring.Bitmap
}

func (a Assignment) String() string {
	return fmt.Sprintf("assignment{Index:%v, Set:%v}", a.Index, a.Set)
}

// Width returns the total number of assignments that can be made from
// a specific region.
//
// The term "assignment" here refers to the set of all subsets of
// `Region.Available` choose `k`, where `k` falls within the range
// [`Region.Bound.A`, `Region.Bound.B`).
//
// The total number of possible assignments is given by the mathematical
// expression: Sum[Binomial[T, x], {x, A, B-1}]. This has no closed form[^1].
//
// This function assumes that the region fields Available, Bound.A, and Bound.B
// are natural numbers, with 0 <= Region.Bound.A < Region.Bound.B <=
// Region.Available + 1.
//
// [^1]: https://mathoverflow.net/questions/17202/sum-of-the-first-k-binomial-coefficients-for-fixed-n
func (r Region) Width() int {
	w := 0
	n := int(r.Compatible.Stats().Cardinality)
	for k := r.Bound.LowerInclusive; k < r.Bound.UpperExclusive; k++ {
		w += Binom(n, k)
	}
	return w
}

// // gosper's hack
// // first
// func NextCombination(x uint) (uint, bool) {
// 	lsb := x & -x
// 	ripple := x + lsb
// 	nextLsb := ripple & -ripple
// 	return succ + (((succ ^ x) / lsb) >> 2), true
// }

// // MapIndicesToElements maps the indices of the combination to the actual elements.
// func MapIndicesToElements(c uint64, bitmapN *roaring.Bitmap) *roaring.Bitmap {
// 	result := roaring.New()
// 	for i := 0; c > 0; i++ {
// 		if c&1 == 1 {
// 			val, err := bitmapN.Select(uint32(i))
// 			if err != nil {
// 				panic(err)
// 			}
// 			result.Add(val)
// 		}
// 		c >>= 1
// 	}
// 	return result
// }

// // NextMaskedCombination generates the next combination that satisfies a mask.
// func NextMaskedCombination(prev *roaring.Bitmap, n, k uint32, bitmapN *roaring.Bitmap) *roaring.Bitmap {
// 	var c uint64
// 	if prev == nil {
// 		c = (1 << uint(k)) - 1
// 	} else {
// 		c = NextCombination(prev.GetCardinality())
// 	}
// 	return MapIndicesToElements(c, bitmapN)
// }

// Combinadic generates the ith k-combination of the set {0, 1, ..., n-1} in
// the combinatorial number system of degree k (Macaulay representation).
//
// It takes a preallocated buffer that should be of size at least k, which is
// encouraged to be reused across calls so long as it's size is at least k, and
// preferably n.
func Combinadic(buffer []int, n int, k int, i int) []int {
	if len(buffer) == 0 {
		buffer = make([]int, k)
	}
	buffer = buffer[:k]
	for k > 0 {
		n--
		for Binom(n, k) > i {
			n--
		}
		i -= Binom(n, k)
		buffer[k-1] = n
		k--
	}
	return buffer
}

var binomCache *lru.TwoQueueCache[[2]int, int]

func init() {
	var err error
	binomCache, err = lru.New2Q[[2]int, int](100) // about 1.2KB
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize binom cache")
	}
}

func Binom(n, k int) int {
	if n < 0 || k < 0 || n < k {
		return 0
	}
	if k > n-k {
		k = n - k // take advantage of symmetry
	}
	if res, ok := binomCache.Get([2]int{n, k}); ok {
		return res
	}
	res := 1
	for i := 1; i <= k; i++ {
		res *= n - (k - i)
		res /= i
	}
	binomCache.Add([2]int{n, k}, res)
	return res
}

type UnsatError struct {
	Reason error
}

func (e UnsatError) Error() string {
	return fmt.Sprintf("unsat: %v", e.Reason)
}

func (e UnsatError) Unwrap() error {
	return e.Reason
}

func Solve(regions []Region) ([]Assignment, error) {
	s := newState(regions)
	asmts, ok := s.solve()
	if !ok {
		return nil, UnsatError{
			Reason: fmt.Errorf("no solution"),
		}
	}
	return asmts, nil
}

type state struct {
	// The regions for which we need to find non-empty, and non-overlapping
	// assignments. All the regions must be satistied for a complete
	// solution
	regions []Region
	// The current partial solution. A solution is only valid when finally
	// len(path) == len(regions), plus other region constraints. Each
	// Assignment corresponds index wise to to a Region from regions.
	path []Assignment
	// The union of set's from our current path's assignments. This will be
	// mutated over the course of non-concurrent backtracking.
	set *roaring.Bitmap
	// Buffer for generating subset i from m choose k. This can be
	// pre-allocated because the order of our backtracking visits
	// combinations k in descending order.
	//
	// TODO: This should be converted to a bitmap buffer, to improve the
	// efficiency of backtracking path filtering.
	combBuf []int
	// The current step, 0-indexed. If the state has not be started, then
	// i < 0.
	i int
}

// takes ownership over regions
func newState(regions []Region) *state {
	sort.Slice(regions, func(i, j int) bool {
		// Minimal Remaining Values heuristic - The width represents
		// number of possible assignments each region. And our DFS pops
		// off right, so we want that to be the smallest values
		// (minimimum remaining values).
		return regions[i].Width() > regions[j].Width() // !!! PURPOSEFULLY REVERSED FOR TESTING
		// return regions[i].Width() < regions[j].Width()
	})
	maxUpperExclusiveBound := lo.Max(lo.Map(regions, func(r Region, i int) int {
		return r.Bound.UpperExclusive
	}))
	var combBuf []int
	if len(regions) > 0 {
		combBuf = make([]int, maxUpperExclusiveBound-1)
	}
	log.Trace().Str("widths", fmt.Sprintf("%v", lo.Map(regions, func(r Region, i int) int { return r.Width() }))).
		Str("regions", fmt.Sprintf("%v", regions)).
		Int("regions_len", len(regions)).
		Msgf("new state")
	return &state{
		regions: regions,
		path:    make([]Assignment, 0, len(regions)),
		set:     roaring.New(),
		combBuf: combBuf,
		i:       -1,
	}
}

const (
	maxCalls       = 100
	maxRegionAsmts = 100
)

// Returns true if the state is solved, false if it is not. Iff true, then
// assignment will be populated with the solution.
func (s *state) solve() ([]Assignment, bool) {
	s.i++
	log.Trace().Int("i", s.i).
		Str("regions", fmt.Sprintf("%v", s.regions)).
		Int("regions_len", len(s.regions)).
		Str("path", fmt.Sprintf("%v", s.path)).
		Int("path_len", len(s.path)).
		Stringer("set_global", s.set).
		Msgf("solve call")
	if s.i > maxCalls {
		log.Warn().Msgf("too many calls, giving up: %d > %d", s.i, maxCalls)
		return nil, false
	}
	// If there are no more regions to assign, we have a solution, as we
	// have been popping regions along our DFS recursive path.
	if len(s.regions) == 0 {
		log.Trace().Msg("base case, no regions left")
		return s.path, true
	}
	// Regions are assumed to be already sorted by some MRV heuristic, with
	// the last item being the most constrained (minimal remaining values).
	r := s.regions[len(s.regions)-1]
	s.regions = s.regions[:len(s.regions)-1]
	log.Trace().Int("regions_remain", len(s.regions)).Msgf("popped region: %v", r)

	// Iteratively check all possible values for the variable
	j := -1
	for {
		if j > maxRegionAsmts {
			log.Warn().Msgf("too many region head assignments, giving up: %d > %d", j, maxRegionAsmts)
			return nil, false
		}
		j++
		h := r.NextHead()
		if h == nil {
			// no more values in this region under this path to try
			if len(s.path) > 0 {
				// If we were to backtrack when there is no
				// previous path, then we are backtracking
				// after everything has failed, leading to an
				// infinite loop.
				r.head = nil
				s.regions = append(s.regions, r)
				log.Trace().Str("path", fmt.Sprintf("%v", s.path)).
					Int("path_len", len(s.path)).
					Msgf("no more heads, backtracking region: %v", r)
			}
			log.Trace().Msg("no more heads on final region, giving up")
			return nil, false
		}
		log.Trace().Int("i", s.i).
			Int("j", j).
			Msgf("attempting head: %v", h)

			// Now we need to generate the next common subset.
			//
			// TODO: Generate the next subset m choose k, and then
			// map back into indices in n choose k, to avoid
			// wastefully iterating over subsets which will
			// conflict with unavailable devices.
		sub := Combinadic(s.combBuf, h.n, h.k, h.i)
		log.Trace().Ints("sub", sub).
			Int("n", h.n).
			Int("k", h.k).
			Int("i", h.i).
			// Ints("buf", s.combBuf).
			Msgf("generated combinadic subset")
		nextSet := roaring.New()
		for _, dev := range sub {
			if !r.Compatible.ContainsInt(dev) {
				// log.Trace().Msgf("incompatible assignment: %d", dev)
				continue
			}
			if s.set.ContainsInt(dev) {
				log.Trace().Msgf("skipping previous assignment: %d", dev)
				continue
			}
			nextSet.Add(uint32(dev))
		}
		if nextSet.IsEmpty() {
			log.Trace().Msg("no compatible devices left for assignment, continuing to next head")
			continue
		}

		s.path = append(s.path, Assignment{
			Index: r.Index,
			Set:   nextSet,
		})
		s.set.Or(nextSet)
		log.Trace().Stringer("set_global", s.set).
			Str("path", fmt.Sprintf("%v", s.path)).
			Int("path_len", len(s.path)).
			Msgf("attempting assignment: %v", nextSet)

		// Attempt a solution given our chosen nextSet assignment for
		// this region head. That is, now we recursively see if whether
		// having chosen this assignment it ends up leading to
		// a solution.
		if sol, ok := s.solve(); ok {
			log.Trace().Str("path", fmt.Sprintf("%v", s.path)).
				Msgf("recursive solve returned true: %d, %d", len(s.path), len(s.regions))
			return sol, true
		}

		// And if it fails, then backtrack.
		s.path = s.path[:len(s.path)-1]
		s.set.AndNot(nextSet) // inverse of s.set.Or(set) from above
		log.Trace().Stringer("set_global", s.set).
			Str("path", fmt.Sprintf("%v", s.path)).
			Int("path_len", len(s.path)).
			Msgf("attempt failed, backtracking")
	}
}

// An Item is something we manage in a priority queue.
type Item[T any, P constraints.Ordered] struct {
	Data     T
	Priority P
	index    int
}

// A PriorityQueue implements heap.Interface and holds Items.
type PriorityQueue[T any, P constraints.Ordered] []*Item[T, P]

func (pq PriorityQueue[T, P]) Len() int { return len(pq) }

func (pq PriorityQueue[T, P]) Less(i, j int) bool {
	return pq[i].Priority > pq[j].Priority
}

func (pq PriorityQueue[T, P]) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue[T, P]) Push(x any) {
	n := len(*pq)
	item := x.(*Item[T, P])
	item.index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue[T, P]) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// // update modifies the priority and value of an Item in the queue.
// func (pq *PriorityQueue[T, P]) update(item *Item[T, P], data T, priority P) {
// 	item.Data = data
// 	item.Priority = priority
// 	heap.Fix(pq, item.index)
// }

// // This example creates a PriorityQueue with some items, adds and manipulates an item,
// // and then removes the items in priority order.
// func main() {
// 	// Some items and their priorities.
// 	items := map[string]int{
// 		"banana": 3, "apple": 2, "pear": 4,
// 	}

// 	// Create a priority queue, put the items in it, and
// 	// establish the priority queue (heap) invariants.
// 	pq := make(PriorityQueue, len(items))
// 	i := 0
// 	for value, priority := range items {
// 		pq[i] = &Item{
// 			value:    value,
// 			priority: priority,
// 			index:    i,
// 		}
// 		i++
// 	}
// 	heap.Init(&pq)

// 	// Insert a new item and then modify its priority.
// 	item := &Item{
// 		value:    "orange",
// 		priority: 1,
// 	}
// 	heap.Push(&pq, item)
// 	pq.update(item, item.value, 5)

// 	// Take the items out; they arrive in decreasing priority order.
// 	for pq.Len() > 0 {
// 		item := heap.Pop(&pq).(*Item)
// 		fmt.Printf("%.2d:%s ", item.priority, item.value)
// 	}
// }

func DefaultLitCoeffs() []int { return nil }

const HardConstraintWeight int = 0

func AtMost1(
	lits []maxsat.Lit,
	coeffs []int,
	weight int,
) maxsat.Constr {
	negated := make([]maxsat.Lit, len(lits))
	for i, lit := range lits {
		negated[i] = lit.Negation()
	}
	return maxsat.Constr{
		Lits:    negated,
		Coeffs:  coeffs,
		AtLeast: len(lits) - 1,
		Weight:  weight,
	}
}

// GtEq returns a pseudo-boolean constraint stating that the sum of all literals multiplied by their coefficients
// must be at least n. The weight of the constraint is set to w.
// Will panic if len(coeffs) != len(lits).
func GtEq(lits []maxsat.Lit, coeffs []int, n int, w int) maxsat.Constr {
	if coeffs == nil {
		coeffs = ones(len(lits))
	}
	if len(coeffs) != len(lits) {
		panic("not as many lits as coeffs")
	}
	return maxsat.Constr{
		Lits:    lits,
		Coeffs:  coeffs,
		AtLeast: n,
		Weight:  w,
	}
}

func ones(n int) []int {
	v := make([]int, n)
	for i := range v {
		v[i] = 1
	}
	return v
}

// LtEq returns a pseudo-boolean constraint stating that the sum of all literals multiplied by their coefficients
// must be at most n. The weight of the constraint is set to w.
// Will panic if len(coeffs) != len(lits).
func LtEq(lits []maxsat.Lit, coeffs []int, n int, w int) maxsat.Constr {
	if coeffs == nil {
		coeffs = ones(len(lits))
	}
	// Negate all literals and adjust the threshold.
	for i := range lits {
		lits[i] = lits[i].Negation()
		n -= coeffs[i]
	}
	return GtEq(lits, coeffs, n, w)
}

// Eq returns a set of pseudo-boolean constraints stating that the sum of all literals multiplied by their coefficients
// must be exactly n. The weight of the constraints is set to w.
// Will panic if len(coeffs) != len(lits).
func Eq(lits []maxsat.Lit, coeffs []int, n int, w int) []maxsat.Constr {
	if coeffs == nil {
		coeffs = ones(len(lits))
	}
	// Create two constraints for the equality: one for the lower bound and one for the upper bound.
	lits2 := make([]maxsat.Lit, len(lits))
	coeffs2 := make([]int, len(coeffs))
	copy(lits2, lits)
	copy(coeffs2, coeffs)
	ge := GtEq(lits2, coeffs2, n, w)
	le := LtEq(lits, coeffs, n, w)
	log.Debug().Str("lits", fmt.Sprintf("%+v", lits)).
		Str("ge", fmt.Sprintf("%#v", ge)).
		Str("le", fmt.Sprintf("%#v", le)).
		Msgf("added eq constraints (2)")
	return []maxsat.Constr{ge, le}
}
