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
)

var inlineLink = regexp.MustCompile(`\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+"[^"\n]*")?\s*\)`)

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
	fmt.Println("Harness: инструкции и навигация проверены")
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
	for _, required := range []string{"docs/architecture.md", "docs/development.md"} {
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
	problems = append(problems, checkADR(root, documents)...)
	sort.Strings(problems)
	return problems
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

func checkADR(root string, documents map[string]string) []string {
	var problems []string
	names := map[string]bool{}
	validName := regexp.MustCompile(`^docs/adr/([0-9]{4})-[a-z0-9-]+\.md$`)
	status := regexp.MustCompile(`(?m)^## Статус\s+\n?(proposed|accepted|superseded|deprecated)\b`)
	date := regexp.MustCompile(`(?m)^## Дата\s+\n?[0-9]{4}-[0-9]{2}-[0-9]{2}\b`)
	index := documents["docs/adr/README.md"]
	for file, content := range documents {
		if !strings.HasPrefix(file, "docs/adr/") || file == "docs/adr/README.md" || file == "docs/adr/template.md" {
			continue
		}
		match := validName.FindStringSubmatch(file)
		if match == nil {
			problems = append(problems, file+": неверное имя ADR")
			continue
		}
		if names[match[1]] {
			problems = append(problems, file+": повторный номер ADR")
		}
		names[match[1]] = true
		for _, section := range []string{"Статус", "Дата", "Контекст", "Решение", "Рассмотренные альтернативы", "Последствия", "Источники"} {
			if !strings.Contains(content, "## "+section) {
				problems = append(problems, file+": отсутствует раздел "+section)
			}
		}
		st := status.FindStringSubmatch(content)
		if st == nil {
			problems = append(problems, file+": неверный статус ADR")
		}
		if !date.MatchString(content) {
			problems = append(problems, file+": неверная дата ADR")
		}
		if st != nil && st[1] == "superseded" && !strings.Contains(content, "## Заменено") {
			problems = append(problems, file+": отсутствует ссылка на замену")
		}
		if !strings.Contains(index, filepath.Base(file)) {
			problems = append(problems, file+": отсутствует в индексе ADR")
		}
	}
	return problems
}
