package rtc

import "testing"

func TestRoomValidation(t *testing.T) {
	c := &PrivateContent{RoomRules: []RoomRule{{Host: "meet.example", PathPattern: `^/j/([0-9]+)$`, Provider: "wbstream"}}}
	for _, bad := range []string{"http://meet.example/j/123", "https://evil.test/j/123", "https://meet.example.evil.test/j/123", "https://user@meet.example/j/123", "https://meet.example:443/j/123", "https://meet.example/j/123?redirect=https://evil.test", "https://meet.example/j/%31", "https://meet.example/j/123#fragment", "https://meet.example/j/123/extra"} {
		if _, _, e := c.ParseRoom(bad); e == nil {
			t.Fatal("accepted", bad)
		}
	}
	p, r, e := c.ParseRoom("https://meet.example/j/123")
	if e != nil || p != "wbstream" || r != "123" {
		t.Fatal("valid room rejected")
	}
}
