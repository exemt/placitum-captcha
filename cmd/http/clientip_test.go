package main

import "testing"

func TestForwardedAddr(t *testing.T) {
	const conn = "172.18.0.5:41234"

	cases := []struct {
		name   string
		values []string
		remote string
		want   string
	}{
		{"узел дописал адрес к присланному клиентом", []string{"6.6.6.6, 203.0.113.7"}, conn, "203.0.113.7"},
		{"узел перезаписал заголовок", []string{"203.0.113.7"}, conn, "203.0.113.7"},
		{"несколько строк: последняя", []string{"6.6.6.6", "198.51.100.1, 203.0.113.7"}, conn, "203.0.113.7"},
		{"IPv6", []string{"6.6.6.6, 2001:db8::7"}, "[fd00::5]:41234", "2001:db8::7"},
		{"заголовка нет", nil, conn, "172.18.0.5"},
		{"пустой хвост -- не значение клиента", []string{"6.6.6.6, "}, conn, "172.18.0.5"},
		{"хвост не адрес", []string{"6.6.6.6, unknown"}, conn, "172.18.0.5"},
		{"адрес соединения без порта", nil, "172.18.0.5", "172.18.0.5"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := forwardedAddr(tc.values, tc.remote); got != tc.want {
				t.Fatalf("forwardedAddr(%q, %q) = %q, want %q", tc.values, tc.remote, got, tc.want)
			}
		})
	}
}
