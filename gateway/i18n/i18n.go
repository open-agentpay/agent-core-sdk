package i18n

import (
	"fmt"
	"strings"
	"sync"
)

const (
	LangZH = "zh"
	LangEN = "en"
)

var (
	mu          sync.RWMutex
	defaultLang = LangZH
	locales     = make(map[string]map[string]string)
)

func init() {
	RegisterLocale(LangZH, MessagesZH)
	RegisterLocale(LangEN, MessagesEN)
}

// RegisterLocale registers or extends a language dictionary.
func RegisterLocale(lang string, msgs map[string]string) {
	mu.Lock()
	defer mu.Unlock()
	cleanLang := strings.ToLower(strings.TrimSpace(lang))
	if locales[cleanLang] == nil {
		locales[cleanLang] = make(map[string]string)
	}
	for k, v := range msgs {
		locales[cleanLang][k] = v
	}
}

// SetDefaultLang sets the global fallback language (defaults to "zh").
func SetDefaultLang(lang string) {
	mu.Lock()
	defer mu.Unlock()
	defaultLang = strings.ToLower(strings.TrimSpace(lang))
}

// Get returns the localized message for a language and key.
func Get(lang string, key string) string {
	mu.RLock()
	defer mu.RUnlock()

	cleanLang := strings.ToLower(strings.TrimSpace(lang))
	if dict, ok := locales[cleanLang]; ok {
		if msg, found := dict[key]; found && msg != "" {
			return msg
		}
	}
	// Fallback to default language
	if dict, ok := locales[defaultLang]; ok {
		if msg, found := dict[key]; found && msg != "" {
			return msg
		}
	}
	// Fallback to English
	if dict, ok := locales[LangEN]; ok {
		if msg, found := dict[key]; found && msg != "" {
			return msg
		}
	}
	return ""
}

// T returns the localized message in the default language ("zh").
func T(key string) string {
	return Get(defaultLang, key)
}

// ZH returns the Chinese message for the key.
func ZH(key string) string {
	return Get(LangZH, key)
}

// EN returns the English message for the key.
func EN(key string) string {
	return Get(LangEN, key)
}

// Format returns a formatted localized string.
func Format(lang string, key string, args ...interface{}) string {
	tpl := Get(lang, key)
	if tpl == "" {
		return ""
	}
	if len(args) == 0 {
		return tpl
	}
	return fmt.Sprintf(tpl, args...)
}

// FormatZH returns a formatted Chinese string.
func FormatZH(key string, args ...interface{}) string {
	return Format(LangZH, key, args...)
}
