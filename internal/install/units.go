package install

import _ "embed"

//go:embed scripts/ultra-relay.service
var RelaySystemdUnit string

//go:embed scripts/ultra-bot.service
var BotSystemdUnit string
