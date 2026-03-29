package core

import "testing"

func TestCountingPoolEmpty(t *testing.T) {
	pool := NewCountingPool[int](nil)
	if pool.Next() != nil {
		t.Fatal("expected nil")
	}
}

func TestCountingPoolDistributesEvenly(t *testing.T) {
	pool := NewCountingPool([]string{"a", "b", "c", "d"})
	counts := map[string]int{}
	for i := 0; i < 400; i++ {
		counts[*pool.Next()]++
	}
	for item, count := range counts {
		if count != 100 {
			t.Errorf("item %q got %d, expected 100", item, count)
		}
	}
}

func TestCountingPoolNextExcluding(t *testing.T) {
	pool := NewCountingPool([]string{"a", "b"})
	for i := 0; i < 10; i++ {
		v := pool.NextExcluding(func(s string) bool { return s == "a" })
		if v == nil || *v != "b" {
			t.Fatalf("expected b")
		}
	}
}
