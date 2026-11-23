package cdp

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

type mousePoint struct {
	X float64
	Y float64
}

func cryptoFloat64() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	// 53-bit uniform float in [0, 1)
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

func randRangeFloat(min, max float64) float64 {
	if max <= min {
		return min
	}
	return min + cryptoFloat64()*(max-min)
}

func randRangeInt(min, max int) int {
	if max <= min {
		return min
	}
	return min + int(cryptoFloat64()*float64(max-min+1))
}

// PickHumanLandingPoint chooses a randomized point within the inner 30%..70% of an element rect, clamped to viewport.
func PickHumanLandingPoint(left, top, width, height, vw, vh float64) (float64, float64) {
	rx := randRangeFloat(0.30, 0.70)
	ry := randRangeFloat(0.30, 0.70)
	x := left + width*rx
	y := top + height*ry
	if vw < 10 {
		vw = 1280
	}
	if vh < 10 {
		vh = 800
	}
	x = math.Max(2, math.Min(vw-2, x))
	y = math.Max(2, math.Min(vh-2, y))
	return x, y
}

// BuildBezierTrajectory generates a realistic cubic Bezier cursor path from a nearby viewport start point to (tx, ty).
func BuildBezierTrajectory(tx, ty, vw, vh float64) []mousePoint {
	return BuildBezierTrajectoryFrom(0, 0, false, tx, ty, vw, vh)
}

// BuildBezierTrajectoryFrom generates a cubic Bezier cursor path from (sx, sy) when hasStart is true,
// or from a realistic nearby viewport point otherwise.
func BuildBezierTrajectoryFrom(sx, sy float64, hasStart bool, tx, ty, vw, vh float64) []mousePoint {
	if vw < 100 {
		vw = 1280
	}
	if vh < 100 {
		vh = 800
	}
	if hasStart {
		sx = math.Max(2, math.Min(vw-2, sx))
		sy = math.Max(2, math.Min(vh-2, sy))
	} else {
		angle := randRangeFloat(0, 2*math.Pi)
		dist := randRangeFloat(120, 360)
		sx = math.Max(12, math.Min(vw-12, tx+math.Cos(angle)*dist))
		sy = math.Max(12, math.Min(vh-12, ty+math.Sin(angle)*dist))
	}

	dx, dy := tx-sx, ty-sy
	dist := math.Hypot(dx, dy)
	perpX, perpY := -dy, dx
	scale := randRangeFloat(-0.25, 0.25)
	c1x := sx + dx*randRangeFloat(0.20, 0.40) + perpX*scale
	c1y := sy + dy*randRangeFloat(0.20, 0.40) + perpY*scale
	c2x := sx + dx*randRangeFloat(0.60, 0.82) + perpX*scale*randRangeFloat(0.3, 1.1)
	c2y := sy + dy*randRangeFloat(0.60, 0.82) + perpY*scale*randRangeFloat(0.3, 1.1)

	steps := randRangeInt(8, 16)
	if dist < 40 {
		steps = randRangeInt(3, 6)
	}
	pts := make([]mousePoint, 0, steps+1)
	for i := 0; i <= steps; i++ {
		rawT := float64(i) / float64(steps)
		// Smoothstep ease-in-out so cursor accelerates then decelerates naturally.
		t := rawT * rawT * (3 - 2*rawT)
		u := 1 - t
		x := u*u*u*sx + 3*u*u*t*c1x + 3*u*t*t*c2x + t*t*t*tx
		y := u*u*u*sy + 3*u*u*t*c1y + 3*u*t*t*c2y + t*t*t*ty
		// Add slight micro-jitter on intermediate points (exact start & landing).
		if i > 0 && i < steps {
			jitter := 1.5
			if dist < 40 {
				jitter = 0.6
			}
			x += randRangeFloat(-jitter, jitter)
			y += randRangeFloat(-jitter, jitter)
		}
		x = math.Max(1, math.Min(vw-1, x))
		y = math.Max(1, math.Min(vh-1, y))
		pts = append(pts, mousePoint{X: x, Y: y})
	}
	return pts
}

// moveMouseHumanized dispatches a multi-step Bezier mouseMoved sequence from the current cursor to (tx, ty).
func (c *Client) moveMouseHumanized(tx, ty, vw, vh float64) (int, error) {
	pts := BuildBezierTrajectoryFrom(c.cursorX, c.cursorY, c.hasCursor, tx, ty, vw, vh)
	for _, p := range pts {
		if _, err := c.Call("Input.dispatchMouseEvent", map[string]any{
			"type":        "mouseMoved",
			"x":           p.X,
			"y":           p.Y,
			"pointerType": "mouse",
		}, 15*time.Second); err != nil {
			return 0, err
		}
		time.Sleep(time.Duration(randRangeInt(8, 22)) * time.Millisecond)
	}
	c.cursorX = tx
	c.cursorY = ty
	c.hasCursor = true
	return len(pts), nil
}
