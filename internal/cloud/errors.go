package cloud

import (
	"context"
	"errors"
	"strings"
)

// Provider text is used only for classification and is never retained or returned.
func providerCode(status int, message string) string {
	m := strings.ToLower(message)
	switch {
	case strings.Contains(m, "insufficient funds") || strings.Contains(m, "insufficient credit") || strings.Contains(m, "insufficient balance") || strings.Contains(m, "not enough funds"):
		return "insufficient_funds"
	case strings.Contains(m, "ip") && (strings.Contains(m, "unauthorized") || strings.Contains(m, "not authorized") || strings.Contains(m, "not allowed") || strings.Contains(m, "whitelist")):
		return "api_ip_denied"
	case strings.Contains(m, "capacity") || strings.Contains(m, "out of stock") || strings.Contains(m, "not available in this location"):
		return "region_unavailable"
	case strings.Contains(m, "account") && (strings.Contains(m, "suspended") || strings.Contains(m, "disabled")):
		return "account_suspended"
	case status == 401:
		return "api_key_invalid"
	case status == 402:
		return "payment_required"
	case status == 403:
		return "api_permission_denied"
	case status == 429:
		return "provider_rate_limit"
	case status >= 500:
		return "provider_unavailable"
	default:
		return "provider_rejected"
	}
}
func ErrorCode(err error) string {
	if errors.Is(err, ErrUnknownCreation) {
		return "creation_requires_reconciliation"
	}
	var api APIError
	if errors.As(err, &api) && api.Code != "" {
		return api.Code
	}
	switch {
	case errors.Is(err, ErrUnknownCreation):
		return "creation_requires_reconciliation"
	case errors.Is(err, ErrLimit):
		return "capacity_limit"
	case errors.Is(err, ErrPriceChanged):
		return "offer_expired_or_changed"
	case errors.Is(err, ErrConflict):
		return "operation_conflict"
	case errors.Is(err, context.DeadlineExceeded):
		return "operation_timeout"
	case errors.Is(err, context.Canceled):
		return "operation_interrupted"
	default:
		return "operation_unavailable"
	}
}
func ErrorMessage(code string) string {
	messages := map[string]string{
		"provider_timeout":                 "Vultr не ответил вовремя. Проверьте журнал: после отправки покупки сначала сверяется её результат.",
		"provider_unreachable":             "Не удалось подключиться к API Vultr. Проверьте сеть и DNS исполнителя на bridge.",
		"insufficient_funds":               "На аккаунте Vultr недостаточно средств. Пополните баланс и получите новое предложение цены.",
		"payment_required":                 "Vultr требует проверки оплаты. Проверьте способ оплаты и состояние аккаунта в панели Vultr.",
		"api_key_invalid":                  "Vultr отклонил API-ключ. Проверьте серверный ключ и включённый доступ к API.",
		"api_ip_denied":                    "Исходящий IP bridge не разрешён для этого API-ключа. Добавьте его в разрешённые адреса Vultr.",
		"api_permission_denied":            "API-ключу не разрешено это действие. Проверьте права управления VPS, SSH-ключами и firewall, а также разрешённые IP.",
		"region_unavailable":               "В выбранном регионе нет доступной мощности для этого тарифа. Выберите другой регион или повторите позже.",
		"account_suspended":                "Аккаунт Vultr ограничен или приостановлен. Проверьте уведомления в панели провайдера.",
		"provider_rate_limit":              "Vultr ограничил частоту запросов. Подождите и повторите проверку.",
		"provider_unavailable":             "Vultr временно не отвечает. Проверьте журнал операции и повторите проверку позже.",
		"provider_rejected":                "Vultr отклонил запрос. Проверьте этап и HTTP-код в журнале операции; неизвестный ответ провайдера скрыт.",
		"capacity_limit":                   "Лимит — два VPS, включая создаваемые и ожидающие удаления. Освободите слот и получите новое предложение.",
		"offer_expired_or_changed":         "Предложение истекло, цена изменилась или тариф недоступен. Отмените незавершённое создание и запросите новую цену.",
		"operation_conflict":               "Действие недоступно в текущем состоянии. Обновите список операций.",
		"creation_requires_reconciliation": "Результат покупки неизвестен. Проверяем VPS по метке операции; повторная покупка не выполняется.",
		"creation_ambiguous":               "Не удалось однозначно найти созданный VPS. Проверьте ресурсы в Vultr по ID операции; покупка не повторяется.",
		"preparation_failed":               "Не удалось подготовить исполнителя: проверьте настройки SSH, репликации и закреплённого бинарника.",
		"installation_failed":              "Не удалось установить Ultra на VPS. Проверьте доступ по SSH и состояние службы. VPS продолжает оплачиваться.",
		"tunnel_verification_failed":       "Новый туннель не прошёл проверку передачи данных. Локация не опубликована; VPS продолжает оплачиваться.",
		"configuration_not_applied":        "Маршруты не подтверждены ядром. Исправьте конфигурацию и повторите применение.",
		"server_deletion_failed":           "Vultr не подтвердил удаление VPS. Ресурс остаётся в лимите; оплата может продолжаться.",
		"old_server_deletion_failed":       "Новый маршрут готов, но удаление прежнего VPS не подтверждено. Оба ресурса остаются в лимите.",
		"operation_timeout":                "Этап превысил время ожидания. Проверьте журнал и повторите продолжение операции.",
		"operation_interrupted":            "Этап прерван. Состояние сохранено для повторного продолжения.",
	}
	if m := messages[code]; m != "" {
		return m
	}
	return "Операция временно недоступна. Проверьте её журнал и повторите действие."
}
