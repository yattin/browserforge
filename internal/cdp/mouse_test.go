package cdp

import (
	"math"
	"testing"
)

func TestPickHumanLandingPointWithinBounds(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 30; i++ {
		x, y := PickHumanLandingPoint(100, 200, 200, 100, 1280, 800)
		if x < 160 || x > 240 || y < 230 || y > 270 {
			t.Fatalf("landing point (%.2f, %.2f) outside expected 30%%-70%% inner box", x, y)
		}
		seen[int(math.Round(x*10))] = true
	}
	if len(seen) < 5 {
		t.Fatalf("expected randomized landing points, got only %d distinct values", len(seen))
	}
}

func TestBuildBezierTrajectory(t *testing.T) {
	pts := BuildBezierTrajectory(500, 400, 1280, 800)
	if len(pts) < 9 || len(pts) > 17 {
		t.Fatalf("unexpected trajectory length %d", len(pts))
	}
	last := pts[len(pts)-1]
	if math.Abs(last.X-500) > 0.01 || math.Abs(last.Y-400) > 0.01 {
		t.Fatalf("trajectory must end at target (500,400), got (%.2f,%.2f)", last.X, last.Y)
	}
	for _, p := range pts {
		if p.X < 1 || p.X > 1279 || p.Y < 1 || p.Y > 799 {
			t.Fatalf("point out of viewport bounds: %+v", p)
		}
	}
}

func TestBuildBezierTrajectoryFromContinuousStart(t *testing.T) {
	pts := BuildBezierTrajectoryFrom(120, 240, true, 500, 400, 1280, 800)
	if len(pts) < 9 {
		t.Fatalf("unexpected short trajectory %d", len(pts))
	}
	if math.Abs(pts[0].X-120) > 0.01 || math.Abs(pts[0].Y-240) > 0.01 {
		t.Fatalf("trajectory must start at (120,240), got (%.2f,%.2f)", pts[0].X, pts[0].Y)
	}
	last := pts[len(pts)-1]
	if math.Abs(last.X-500) > 0.01 || math.Abs(last.Y-400) > 0.01 {
		t.Fatalf("trajectory must end at (500,400), got (%.2f,%.2f)", last.X, last.Y)
	}
}
