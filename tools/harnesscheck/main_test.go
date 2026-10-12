package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture() map[string]string {
	return map[string]string{
		"AGENTS.md":            "# Инструкции\n[Архитектура](docs/architecture.md)\n[Разработка](docs/development.md)\n",
		"docs/architecture.md": "# Архитектура\n[Код](../example.go)\n",
		"docs/development.md":  "# Разработка\nПроверяем релевантные пакеты.\n",
		"example.go":           "package example\n",
	}
}

func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for file, content := range files {
		path := filepath.Join(root, file)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name   string
		change func(map[string]string)
		want   string
	}{
		{name: "valid documentation without decision records"},
		{name: "missing architecture", change: func(f map[string]string) {
			delete(f, "docs/architecture.md")
		}, want: "отсутствует обязательная страница"},
		{name: "missing development", change: func(f map[string]string) {
			delete(f, "docs/development.md")
		}, want: "отсутствует обязательная страница"},
		{name: "code change without doc update", change: func(f map[string]string) {
			f["example.go"] += "\nfunc Updated() {}\n"
		}},
		{name: "broken local link", change: func(f map[string]string) {
			f["docs/development.md"] += "[Missing](missing.md)\n"
		}, want: "ссылка на недоступный файл"},
		{name: "unreachable page", change: func(f map[string]string) {
			f["docs/orphan.md"] = "# Orphan\n"
		}, want: "страница недоступна"},
		{name: "unreachable cycle", change: func(f map[string]string) {
			f["docs/a.md"] = "[B](b.md)"
			f["docs/b.md"] = "[A](a.md)"
		}, want: "страница недоступна"},
		{name: "over instruction limit", change: func(f map[string]string) {
			f["AGENTS.md"] += strings.Repeat("extra\n", 120)
		}, want: "больше 120 строк"},
		{name: "exact instruction limit CRLF", change: func(f map[string]string) {
			f["AGENTS.md"] += strings.Repeat("extra\n", 120-strings.Count(f["AGENTS.md"], "\n"))
			f["AGENTS.md"] = strings.ReplaceAll(f["AGENTS.md"], "\n", "\r\n")
		}},
		{name: "code examples not links", change: func(f map[string]string) {
			f["docs/development.md"] += "\n```md\n[Missing](missing.md)\n```\n~~~\n[Also](absent.md)\n~~~\n`[Inline](nothing.md)`\n"
		}},
		{name: "code example not navigation", change: func(f map[string]string) {
			f["docs/orphan.md"] = "# Orphan"
			f["AGENTS.md"] += "\n```md\n[Orphan](docs/orphan.md)\n```\n"
		}, want: "страница недоступна"},
		{name: "external and fragment links", change: func(f map[string]string) {
			f["docs/development.md"] += "[Web](https://example.invalid/a) [Local](#section) [Mail](mailto:test@example.invalid)\n"
		}},
		{name: "path encoding and code label", change: func(f map[string]string) {
			f["source file.go"] = "package source"
			f["docs/development.md"] += "[`Source`](../source%20file.go#L1) [Source](<../source file.go>)"
		}},
		{name: "escaping repository", change: func(f map[string]string) {
			f["AGENTS.md"] += "[Escape](../outside.md)"
		}, want: "выходит за пределы"},
		{name: "absolute machine path", change: func(f map[string]string) {
			f["AGENTS.md"] += "[Machine](/Users/example/file.md)"
		}, want: "относительную ссылку"},
		{name: "missing entry point", change: func(f map[string]string) {
			delete(f, "AGENTS.md")
		}, want: "AGENTS.md:"},
		{name: "empty entry point", change: func(f map[string]string) {
			f["AGENTS.md"] = "\n"
		}, want: "пустой документ"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := fixture()
			if tc.change != nil {
				tc.change(files)
			}
			root := writeFixture(t, files)
			got := strings.Join(check(root), "\n")
			if (tc.want == "" && got != "") || (tc.want != "" && !strings.Contains(got, tc.want)) {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
			// Both successful and failed validation must leave the input files unchanged.
			for file, before := range files {
				after, err := os.ReadFile(filepath.Join(root, file))
				if err != nil || string(after) != before {
					t.Fatalf("validator changed %s: %v", file, err)
				}
			}
		})
	}
}

func TestADRContracts(t *testing.T) {
	doc := "# 0001 — Decision\n\n## Статус\n\naccepted\n\n## Дата\n\n2026-10-12\n\n## Контекст\n\nReason\n\n## Решение\n\nChoice\n\n## Рассмотренные альтернативы\n\nAlternatives\n\n## Последствия\n\nLimits\n\n## Источники\n\nSources\n"
	file := "docs/adr/0001-decision.md"
	documents := map[string]string{file: doc, "docs/adr/README.md": "[Decision](0001-decision.md)"}
	if got := checkADR("", documents); len(got) != 0 {
		t.Fatal(got)
	}
	documents[file] = strings.Replace(doc, "accepted", "temporary", 1)
	if got := checkADR("", documents); len(got) == 0 {
		t.Fatal("invalid status accepted")
	}
	documents[file] = strings.Replace(doc, "accepted", "superseded", 1)
	if got := checkADR("", documents); len(got) == 0 {
		t.Fatal("missing replacement accepted")
	}
}
