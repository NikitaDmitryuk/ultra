// harnesscheck validates repository documentation without changing files or using the network.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	inlineLink = regexp.MustCompile(`\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+"[^"\n]*")?\s*\)`)
	adrName    = regexp.MustCompile(`^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$`)
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	problems := check(*root)
	for _, problem := range problems {
		fmt.Fprintln(os.Stderr, problem)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	fmt.Println("Harness: инструкции, навигация и ADR проверены")
}

func check(root string) []string {
	var problems []string
	report := func(file, message string) {
		problems = append(problems, file+": "+message)
	}
	files := []string{"AGENTS.md"}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".md") {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		report("docs", err.Error())
	}
	documents := map[string]string{}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			report(file, err.Error())
			continue
		}
		content := strings.ReplaceAll(string(data), "\r\n", "\n")
		if strings.TrimSpace(content) == "" {
			report(file, "пустой документ")
		}
		if file == "AGENTS.md" && len(strings.Split(strings.TrimSuffix(content, "\n"), "\n")) > 120 {
			report(file, "больше 120 строк: перенесите детали в тематическую документацию")
		}
		documents[file] = withoutCode(content)
	}
	for _, required := range []string{"docs/architecture.md", "docs/development.md", "docs/adr/README.md", "docs/adr/template.md"} {
		if _, ok := documents[required]; !ok {
			report(required, "отсутствует обязательная страница")
		}
	}

	links := map[string][]string{}
	for file, content := range documents {
		for _, destination := range destinations(content) {
			target, err := localTarget(file, destination)
			if err != nil {
				report(file, err.Error())
				continue
			}
			if target == "" { // External URL or same-page fragment.
				continue
			}
			if _, err := os.Stat(filepath.Join(root, target)); err != nil {
				report(file, "ссылка на недоступный файл: "+destination)
				continue
			}
			links[file] = append(links[file], target)
		}
	}
	visited := map[string]bool{}
	queue := []string{"AGENTS.md"}
	for len(queue) > 0 {
		file := queue[0]
		queue = queue[1:]
		if visited[file] {
			continue
		}
		visited[file] = true
		queue = append(queue, links[file]...)
	}
	for file := range documents {
		if !visited[file] {
			report(file, "страница недоступна из AGENTS.md: добавьте ссылку в навигацию")
		}
	}
	checkADRs(documents, links, report)
	sort.Strings(problems)
	return problems
}

func checkADRs(documents map[string]string, links map[string][]string, report func(string, string)) {
	ids := map[string]string{}
	records := map[string]map[string]string{}
	for file, content := range documents {
		if !strings.HasPrefix(file, "docs/adr/") || file == "docs/adr/README.md" || file == "docs/adr/template.md" {
			continue
		}
		match := adrName.FindStringSubmatch(strings.TrimPrefix(file, "docs/adr/"))
		if match == nil {
			report(file, "имя ADR должно иметь вид NNNN-short-title.md")
			continue
		}
		if previous, ok := ids[match[1]]; ok {
			report(file, "повторный номер ADR: "+previous)
		}
		ids[match[1]] = file
		sections := sectionsOf(content)
		records[file] = sections
		for _, heading := range []string{"Статус", "Дата", "Контекст", "Решение", "Рассмотренные альтернативы", "Последствия", "Источники"} {
			if strings.TrimSpace(sections[heading]) == "" {
				report(file, "отсутствует или пуст раздел: "+heading)
			}
		}
		switch strings.TrimSpace(sections["Статус"]) {
		case "proposed", "accepted", "superseded", "deprecated":
		default:
			report(file, "неверный статус ADR")
		}
		if _, err := time.Parse("2006-01-02", strings.TrimSpace(sections["Дата"])); err != nil {
			report(file, "дата ADR должна иметь формат YYYY-MM-DD")
		}
		if !contains(links["docs/adr/README.md"], file) {
			report(file, "ADR отсутствует в ссылках индекса docs/adr/README.md")
		}
	}
	if len(records) == 0 {
		report("docs/adr", "нет ни одного ADR")
	}
	for file, sections := range records {
		if strings.TrimSpace(sections["Статус"]) != "superseded" {
			continue
		}
		valid := false
		for _, destination := range destinations(sections["Заменено"]) {
			target, err := localTarget(file, destination)
			if _, exists := records[target]; err == nil && exists && target != file {
				valid = true
			}
		}
		if !valid {
			report(file, "superseded требует раздел Заменено со ссылкой на другой ADR")
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sectionsOf(content string) map[string]string {
	sections := map[string]string{}
	heading := ""
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "## ") {
			heading = strings.TrimSpace(strings.TrimPrefix(line, "## "))
		} else if heading != "" {
			sections[heading] += line + "\n"
		}
	}
	return sections
}

// Only inline Markdown links are navigation; the repository guide specifies this format.
func destinations(content string) []string {
	var result []string
	for _, match := range inlineLink.FindAllStringSubmatch(content, -1) {
		result = append(result, strings.Trim(match[1], "<>"))
	}
	return result
}

func localTarget(source, destination string) (string, error) {
	u, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("неверная ссылка %q", destination)
	}
	if u.Scheme == "file" {
		return "", fmt.Errorf("используйте относительную ссылку: %s", destination)
	}
	if u.Scheme != "" || u.Host != "" || u.Path == "" {
		return "", nil
	}
	if filepath.IsAbs(u.Path) {
		return "", fmt.Errorf("используйте относительную ссылку: %s", destination)
	}
	target := filepath.Clean(filepath.Join(filepath.Dir(source), filepath.FromSlash(u.Path)))
	if target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("ссылка выходит за пределы репозитория: %s", destination)
	}
	return filepath.ToSlash(target), nil
}

// Keep prose while removing fenced blocks and inline code, so examples aren't checked as links.
func withoutCode(content string) string {
	var result strings.Builder
	var fence byte
	fenceSize := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 3 && (trimmed[0] == '`' || trimmed[0] == '~') {
			n := 0
			for n < len(trimmed) && trimmed[n] == trimmed[0] {
				n++
			}
			if fence == 0 && n >= 3 {
				fence, fenceSize = trimmed[0], n
				continue
			}
			if trimmed[0] == fence && n >= fenceSize && strings.TrimSpace(trimmed[n:]) == "" {
				fence = 0
				continue
			}
		}
		if fence == 0 {
			result.WriteString(withoutInlineCode(line))
			result.WriteByte('\n')
		}
	}
	return result.String()
}

func withoutInlineCode(line string) string {
	for start := 0; start < len(line); {
		offset := strings.IndexByte(line[start:], '`')
		if offset < 0 {
			break
		}
		start += offset
		n := 1
		for start+n < len(line) && line[start+n] == '`' {
			n++
		}
		end := strings.Index(line[start+n:], strings.Repeat("`", n))
		if end < 0 {
			start += n
			continue
		}
		end += start + 2*n
		line = line[:start] + strings.Repeat(" ", end-start) + line[end:]
		start = end
	}
	return line
}
