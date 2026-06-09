package csp_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/RoaringBitmap/roaring"
	"github.com/arclabs561/netwatch/cmd/internal/csp"
	"github.com/arclabs561/netwatch/internal/logutil"
	"github.com/rs/zerolog"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"golang.org/x/exp/constraints"
)

func init() {
	logutil.InitGlobalLogger(context.Background(), logutil.LoggerOptions{
		Level:  mo.Some(zerolog.TraceLevel),
		Format: mo.Some("console"),
		Color:  mo.Some("always"),
	})
}

func TestSolveEmpty(t *testing.T) {
	regions := [][]csp.Region{nil, {}}
	for _, regions := range regions {
		asmts, err := csp.Solve(regions)
		if err != nil {
			t.Fatalf("failed to solve: %+v", err)
		}
		if len(asmts) != 0 {
			t.Fatalf("expected no assignments, got %d: %#v", len(asmts), asmts)
		}
	}
}

// // With just one region, we expect the final number of assignments to be the
// // maxmum compatible.
// func FuzzSingleAtMost(f *testing.F) {
// 	for n := 1; n <= 4; n++ {
// 		for k := 0; k <= n; k++ {
// 			f.Add(n, 1, k+1)
// 			f.Add(n, k, n)
// 		}
// 	}
// 	f.Fuzz(func(t *testing.T, n int, a int, b int) {
// 		if n > 10 {
// 			t.Skip()
// 		}
// 		asmts, err := csp.Solve([]csp.Region{{
// 			Index:      [2]int{0, 0}, // single region, single clause
// 			Compatible: avail(n),
// 			Bound: csp.Bound{
// 				LowerInclusive: a,
// 				UpperExclusive: b,
// 			},
// 		}})
// 		if err != nil {
// 			t.Fatalf("failed to solve: %v", err)
// 		}
// 		if len(asmts) != b-1 {
// 			t.Fatalf("expected exactly %d assignment, got %d: %#v", b-1, len(asmts), asmts)
// 		}
// 	})
// }

func TestSolveSingleAtMost(t *testing.T) {
	n := 4
	for k := 1; k <= n; k++ {
		t.Run(fmt.Sprintf("n=%d,k=%d", n, k), func(t *testing.T) {
			asmts, err := csp.Solve([]csp.Region{
				{
					Index:      [2]int{0, 0}, // single region, single clause
					Compatible: availBitmap(n),
					Bound: csp.Bound{
						LowerInclusive: 1,
						UpperExclusive: k + 1,
					},
				},
			})
			if err != nil {
				t.Fatalf("failed to solve: %+v", err)
			}
			if len(asmts) != 1 {
				t.Fatalf("expected 1 assignment, got %d: %#v", len(asmts), asmts)
			}
			if c := asmts[0].Set.GetCardinality(); c != uint64(k) {
				t.Fatalf("expected %d assignment, got %d: %#v", k, c, asmts)
			}
		})
	}
}

func TestSolveMulti(t *testing.T) {
	// ^wl:h=static,b=2.4+h=uniform,n=1 -i ^wlp0s20f0u2u2:h=uniform,b=5,n=3
	regions := []csp.Region{
		{
			Index:      [2]int{0, 0},
			Compatible: availBitmap(14),
			Bound:      csp.BoundAtLeast(1, 14),
		},
		{
			Index:      [2]int{0, 1},
			Compatible: availBitmap(14),
			Bound:      csp.BoundExactly(1),
		},
	}
	asmts, err := csp.Solve(regions)
	if err != nil {
		t.Fatalf("failed to solve: %+v", err)
	}
	if len(asmts) != 3 {
		t.Fatalf("expected %d assignments, got %d: %v", 3, len(asmts), asmts)
	}
}

// func TestNextMaskedCombination(t *testing.T) {
// 	n, k := 4, 2
// 	// bitmap := roaring.BitmapOf(arange(0, uint32(n), 1)...)
// 	x := uint((1 << k) - 1)
// 	fmt.Printf("init: %04b\n", x)
// 	for i := 0; i < csp.Binom(n, k); i++ {
// 		x = csp.NextCombination(x)
// 		fmt.Printf("next: %04b\n", x)
// 	}
// }

func TestCombinadic(t *testing.T) {
	type testCase struct {
		n, k, i int
		want    []int
	}
	tests := []testCase{
		{1, 1, 0, []int{0}},                    // Minimum values test.
		{10, 2, 10, []int{0, 5}},               // Checking scenario where k << n.
		{10, 5, 10, []int{1, 2, 3, 4, 6}},      // Checking larger values of n and k, with i > k.
		{13, 7, 6, []int{0, 2, 3, 4, 5, 6, 7}}, // Checking for arbitrary larger numbers.
		{2, 1, 1, []int{1}},                    // i is equal to k (and less than n).
		{3, 2, 1, []int{0, 2}},                 // When i < k and n > k.
		{5, 3, 0, []int{0, 1, 2}},              // When i = 0 (smallest index).
		{5, 3, 10, []int{2, 3, 4}},             // When i = "n choose k" (largest index).
		{5, 3, 2, []int{0, 2, 3}},              // When i = "n choose k" / 2 (middle index).
		{5, 3, 5, []int{0, 2, 4}},              // When i < "n choose k".
		{6, 3, 5, []int{0, 2, 4}},              // When n > k and k = n/2.
		{7, 2, 10, []int{0, 5}},                // When n > k and n is odd.
		{7, 5, 3, []int{0, 1, 3, 4, 5}},        // When n > k and both are odd.
		{8, 3, 10, []int{0, 1, 5}},             // When n > k and n is even.
		{8, 5, 10, []int{1, 2, 3, 4, 6}},       // When n > k and k > n/2.
		{7, 5, 0, []int{0, 1, 2, 3, 4}},        // When i=0 and n > k; should return the first combination.
		{7, 5, 21, []int{2, 3, 4, 5, 6}},       // When i = "n choose k"; should return the last combination.

	}
	maxK := lo.Max(lo.Map(tests, func(tc testCase, index int) int {
		return tc.k
	}))
	buffer := make([]int, maxK)
	for _, tc := range tests {
		got := csp.Combinadic(buffer, tc.n, tc.k, tc.i)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("combinadic(%v, %v, %v) = %v, want %v", tc.n, tc.k, tc.i, got, tc.want)
		}
	}
}

func TestBinom(t *testing.T) {
	testCases := []struct {
		n, k int
		want int
	}{
		{5, 3, 10},
		{10, 2, 45},
		{6, 4, 15},
		{7, 0, 1},
		{8, 8, 1},
		{0, 0, 1},
		{10, 5, 252},
		{7, 7, 1},
	}

	for _, tc := range testCases {
		if got := csp.Binom(tc.n, tc.k); got != tc.want {
			t.Errorf("binom(%v, %v) = %v, want %v", tc.n, tc.k, got, tc.want)
		}
	}
}

func arange[T constraints.Ordered](start, stop, step T) []T {
	var a []T
	for i := start; i < stop; i += step {
		a = append(a, i)
	}
	return a
}

func availBitmap(n int) *roaring.Bitmap {
	return roaring.BitmapOf(lo.Map(arange(0, n, 1), func(i int, _ int) uint32 {
		return uint32(i)
	})...)
}

func TestWidth(t *testing.T) {
	type testCase struct {
		Available  int
		LowerBound int
		UpperBound int
		Expect     int
	}
	testCases := []testCase{
		{0, 0, 1, 1},     // 1 ways to choose 0 from 0
		{1, 0, 1, 1},     // 1 way to choose 0 from 1
		{1, 1, 2, 1},     // 1 way to choose 1 from 1
		{1, 1, 3, 1},     // 1 ways to choose 1 or 2 from 1
		{1, 2, 3, 0},     // 0 ways to choose 2 from 1
		{2, 1, 2, 2},     // 2 ways to choose 1 from 2
		{2, 1, 3, 3},     // 2 ways to choose 1 or 2 from 2
		{2, 1, 4, 3},     // 2 ways to choose 1, 2 or 3 from 2
		{2, 3, 4, 0},     // 0 ways to choose 3 from 2
		{3, 1, 2, 3},     // 3 ways to choose 1 from 3
		{4, 0, 5, 16},    // Sum[Binomial[4, k], {k, 0, 4}]
		{10, 3, 13, 968}, // Sum[Binomial[10, k], {k, 3, 12}]
	}
	for _, tc := range testCases {
		r := csp.Region{
			Compatible: availBitmap(tc.Available),
			Bound:      csp.Bound{tc.LowerBound, tc.UpperBound},
		}
		if got := r.Width(); got != tc.Expect {
			t.Errorf(
				"avail=%d, b=[%d, %d), expected %d != %d actual",
				tc.Available,
				tc.LowerBound,
				tc.UpperBound,
				tc.Expect,
				got,
			)
		}
	}
}

func BenchmarkCombinadic(b *testing.B) {
	buffer := make([]int, 1000)
	for i := 0; i < b.N; i++ {
		csp.Combinadic(buffer, 1000, 500, i%1000)
	}
}
