package dataset

import "testing"

/*
 * Пачка едет без value -- и проверка кадра обязана её пропускать: прежняя
 * «value непустой» отвергала каждую пачку до keeper, и бан по анонсам и
 * составу системы молча не записывался, стоило префиксов оказаться больше
 * одного.
 */
func TestEventCheck(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		ok   bool
	}{
		{"one value", Event{Set: "ban", Value: "8.8.8.8"}, true},
		{"batch without value", Event{Set: "ban", Values: []string{"8.8.4.0/24", "8.8.8.0/24"}}, true},
		{"no set", Event{Values: []string{"8.8.8.0/24"}}, false},
		{"nothing to write", Event{Set: "ban"}, false},
	}

	for _, tc := range cases {
		if err := tc.ev.check(); (err == nil) != tc.ok {
			t.Fatalf("%s: check = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}
