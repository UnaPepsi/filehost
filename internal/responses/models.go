package responses

type Error struct {
	StatusCode uint8
	Message string
	Ratelimit int
}

func (err *Error)IsRatelimited() bool {
	return err.Ratelimit == 0
}
