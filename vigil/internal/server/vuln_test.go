package server

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1:1.0", "2.0", 1},
		{"1.9.5p1", "1.9.5p2", -1},
		{"1.9.5p2", "1.9.5", 1},
		{"3.0.2-0ubuntu1.10", "3.0.7", -1},
		{"9.6p1-3ubuntu13.4", "9.8p1", -1},
		{"0.105-33", "0.120", -1},
		{"5.6.1", "5.6.0", 1},
		{"2.0-1", "2.0-10", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if Affected("5.6.1+really5.4.5-1", "5.6.0", "5.6.2") {
		t.Error("+really versions must compare as the real upstream version")
	}
	if !Affected("5.6.1", "5.6.0", "5.6.2") || Affected("5.4.5", "5.6.0", "5.6.2") {
		t.Error("introduced/fixed range")
	}
}
