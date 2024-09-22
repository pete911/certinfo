// This file contains time-related utilities.

package timex

import (
	"fmt"
	"time"
)

// Diff calculates the absolute difference between 2 time instances in
// years, months, days, hours, minutes and seconds.
//
// For details, see https://stackoverflow.com/a/36531443/1705598
func Diff(a, b time.Time) (year, month, day, hour, min, sec int) {
	if a.Location() != b.Location() {
		b = b.In(a.Location())
	}
	if a.After(b) {
		a, b = b, a
	}
	y1, M1, d1 := a.Date()
	y2, M2, d2 := b.Date()

	h1, m1, s1 := a.Clock()
	h2, m2, s2 := b.Clock()

	year = int(y2 - y1)
	month = int(M2 - M1)
	day = int(d2 - d1)
	hour = int(h2 - h1)
	min = int(m2 - m1)
	sec = int(s2 - s1)

	// Normalize negative values
	if sec < 0 {
		sec += 60
		min--
	}
	if min < 0 {
		min += 60
		hour--
	}
	if hour < 0 {
		hour += 24
		day--
	}
	if day < 0 {
		// days in month:
		t := time.Date(y1, M1, 32, 0, 0, 0, 0, time.UTC)
		day += 32 - t.Day()
		month--
	}
	if month < 0 {
		month += 12
		year--
	}

	return
}

// WeekStartTime returns the time instant pointing to the start of the (ISO) week denoted
// by the given timestamp. Weeks are interpreted starting on Monday,
// so the returned instant will be 00:00 UTC of Monday of the designated week.
//
// This function only returns the given week's first day (Monday), because the
// last day of the week is always its first day + 6 days.
func WeekStartTime(t time.Time) time.Time {
	year, month, day := t.UTC().Date()
	t = time.Date(year, month, day, 0, 0, 0, 0, time.UTC)

	if wd := t.Weekday(); wd == time.Sunday {
		return t.AddDate(0, 0, -6)
	} else {
		return t.AddDate(0, 0, -int(wd)+1)
	}
}

// WeekStart returns the time instant pointing to the start of the week given
// by its year and ISO Week. Weeks are interpreted starting on Monday,
// so the returned instant will be 00:00 UTC of Monday of the designated week.
//
// One nice property of this function is that it handles out-of-range weeks nicely.
// That is, if you pass 0 for the week, it will be interpreted as the last week
// of the previous year. If you pass -1 for the week, it will designate
// the second to last week of the previous year. Similarly, if you pass max week
// of the year plus 1, it will be interpreted as the first week of the next year etc.
//
// This function only returns the given week's first day (Monday), because the
// last day of the week is always its first day + 6 days.
//
// For details, see https://stackoverflow.com/a/52303730/1705598
func WeekStart(year, week int) time.Time {
	// Start from the middle of the year:
	t := time.Date(year, 7, 1, 0, 0, 0, 0, time.UTC)

	// Roll back to Monday:
	// (NOTE: do not call WeekStartTime() for performance reasons: t already has 0 time)
	if wd := t.Weekday(); wd == time.Sunday {
		t = t.AddDate(0, 0, -6)
	} else {
		t = t.AddDate(0, 0, -int(wd)+1)
	}

	// Difference in weeks:
	_, w := t.ISOWeek()
	t = t.AddDate(0, 0, (week-w)*7)

	return t
}

var months = map[string]time.Month{}

func init() {
	for i := time.January; i <= time.December; i++ {
		name := i.String()
		months[name] = i
		months[name[:3]] = i
	}
}

// ParseMonth parses a month given by its name.
// Both long names such as "January", "February" and short names such as
// "Jan", "Feb" are recognized.
//
// For details, see https://stackoverflow.com/a/59681275/1705598
func ParseMonth(s string) (time.Month, error) {
	if m, ok := months[s]; ok {
		return m, nil
	}

	return time.January, fmt.Errorf("invalid month '%s'", s)
}

var weekdays = map[string]time.Weekday{}

func init() {
	for d := time.Sunday; d <= time.Saturday; d++ {
		name := d.String()
		weekdays[name] = d
		weekdays[name[:3]] = d
	}
}

// ParseWeekday parses a weekday given by its name.
// Both long names such as "Monday", "Tuesday" and short names such as
// "Mon", "Tue" are recognized.
//
// For details, see https://stackoverflow.com/a/52456320/1705598
func ParseWeekday(s string) (time.Weekday, error) {
	if d, ok := weekdays[s]; ok {
		return d, nil
	}

	return time.Sunday, fmt.Errorf("invalid weekday '%s'", s)
}
