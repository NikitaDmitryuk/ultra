package main

import (
	"fmt"
	"os"
)

type installWarnings struct {
	msgs []string
}

func (w *installWarnings) add(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, "WARNING:", msg)
	w.msgs = append(w.msgs, msg)
}

func (w *installWarnings) printSummary() {
	if len(w.msgs) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("========== Предупреждения установки ==========")
	for _, m := range w.msgs {
		fmt.Println(" •", m)
	}
	fmt.Println("Установка завершена, но перечисленные шаги пропущены (хост недоступен или ошибка SSH).")
}
