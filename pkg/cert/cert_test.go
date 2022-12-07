package cert

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_expiryFormat(t *testing.T) {
	t.Run("given certificate expiry is more than a year then year is returned as well", func(t *testing.T) {
		v := expiryFormat(getTime(3, 2, 7, 5, 25))
		assert.Equal(t, "3 years 2 months 7 days 5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than a year then year is not returned", func(t *testing.T) {
		v := expiryFormat(getTime(0, 2, 7, 5, 25))
		assert.Equal(t, "2 months 7 days 5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than a month then year and month is not returned", func(t *testing.T) {
		v := expiryFormat(getTime(0, 0, 7, 5, 25))
		assert.Equal(t, "7 days 5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than a day then year, month and day is not returned", func(t *testing.T) {
		v := expiryFormat(getTime(0, 0, 0, 5, 25))
		assert.Equal(t, "5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than an hour then only minutes are returned", func(t *testing.T) {
		v := expiryFormat(getTime(0, 0, 0, 0, 25))
		assert.Equal(t, "25 minutes", v)
	})
}

// --- helper functions ---

func getTime(years, months, days, hours, minutes int) time.Time {
	return time.Now().AddDate(years, months, days).
		Add(time.Hour*time.Duration(hours) + time.Minute*time.Duration(minutes))
}
